import requests
from bs4 import BeautifulSoup
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from xhtml2pdf import pisa
from io import BytesIO
import json
import re

from .models import Scan, Target, Vulnerability, Report

def calculate_score(vulnerabilities):
    score = 100
    for v in vulnerabilities:
        if v['severity'] == 'critical':
            score -= 20
        elif v['severity'] == 'high':
            score -= 10
        elif v['severity'] == 'medium':
            score -= 5
        elif v['severity'] == 'low':
            score -= 2
    return max(0, score)


def check_security_headers(url):
    vulnerabilities = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers

        if 'Strict-Transport-Security' not in headers:
            vulnerabilities.append({
                'name': 'Missing HSTS Header',
                'description': 'The Strict-Transport-Security header is not set. This allows attackers to downgrade HTTPS to HTTP.',
                'severity': 'medium',
                'owasp_category': 'A05:2021',
                'affected_url': url,
                'evidence': 'Header not present in HTTP response',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            })

        if 'Content-Security-Policy' not in headers:
            vulnerabilities.append({
                'name': 'Missing Content Security Policy',
                'description': 'No CSP header found. This increases the risk of XSS attacks.',
                'severity': 'medium',
                'owasp_category': 'A05:2021',
                'affected_url': url,
                'evidence': 'Content-Security-Policy header not present',
                'recommendation': 'Implement a Content-Security-Policy header to prevent XSS.'
            })

        if 'X-Frame-Options' not in headers:
            vulnerabilities.append({
                'name': 'Missing X-Frame-Options',
                'description': 'The X-Frame-Options header is not set, allowing clickjacking attacks.',
                'severity': 'medium',
                'owasp_category': 'A05:2021',
                'affected_url': url,
                'evidence': 'X-Frame-Options header not present',
                'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
            })

        if 'X-Content-Type-Options' not in headers:
            vulnerabilities.append({
                'name': 'Missing X-Content-Type-Options',
                'description': 'The X-Content-Type-Options header is missing, allowing MIME sniffing.',
                'severity': 'low',
                'owasp_category': 'A05:2021',
                'affected_url': url,
                'evidence': 'X-Content-Type-Options header not present',
                'recommendation': 'Add: X-Content-Type-Options: nosniff'
            })

    except requests.exceptions.SSLError:
        vulnerabilities.append({
            'name': 'SSL Certificate Error',
            'description': 'The SSL certificate is invalid or expired.',
            'severity': 'high',
            'owasp_category': 'A02:2021',
            'affected_url': url,
            'evidence': 'SSL verification failed',
            'recommendation': 'Renew or fix the SSL certificate immediately.'
        })
    except Exception as e:
        pass

    return vulnerabilities


def check_ssl(url):
    vulnerabilities = []
    if url.startswith('http://'):
        vulnerabilities.append({
            'name': 'No HTTPS Encryption',
            'description': 'The website is served over HTTP not HTTPS. All data is transmitted in plain text.',
            'severity': 'high',
            'owasp_category': 'A02:2021',
            'affected_url': url,
            'evidence': 'URL uses HTTP protocol',
            'recommendation': 'Enable HTTPS with a valid SSL/TLS certificate immediately.'
        })
    return vulnerabilities


def check_xss(url, forms):
    vulnerabilities = []
    xss_payloads = [
        '<script>alert("xss")</script>',
        '"><script>alert(1)</script>',
        "';alert('xss');//",
    ]
    for form in forms[:3]:
        action = form.get('action', url)
        if not action.startswith('http'):
            action = url + action
        inputs = form.find_all('input')
        for payload in xss_payloads[:1]:
            data = {}
            for inp in inputs:
                name = inp.get('name', '')
                if name:
                    data[name] = payload
            try:
                response = requests.post(action, data=data, timeout=8, verify=False)
                if payload in response.text:
                    vulnerabilities.append({
                        'name': 'Reflected XSS Vulnerability',
                        'description': 'A cross-site scripting vulnerability was found. User input is reflected in the response without sanitisation.',
                        'severity': 'high',
                        'owasp_category': 'A03:2021',
                        'affected_url': action,
                        'evidence': f'Payload reflected: {payload[:50]}',
                        'recommendation': 'Sanitise and encode all user input before rendering in HTML. Implement a Content Security Policy.'
                    })
                    break
            except Exception:
                pass
    return vulnerabilities


def check_sqli(url, forms):
    vulnerabilities = []
    sqli_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
    ]
    error_signatures = [
        'sql syntax', 'mysql_fetch', 'ora-01756',
        'sqlite_', 'postgresql', 'warning: pg_',
        'unclosed quotation', 'quoted string not properly terminated'
    ]
    for form in forms[:3]:
        action = form.get('action', url)
        if not action.startswith('http'):
            action = url + action
        inputs = form.find_all('input')
        for payload in sqli_payloads[:2]:
            data = {}
            for inp in inputs:
                name = inp.get('name', '')
                if name:
                    data[name] = payload
            try:
                response = requests.post(action, data=data, timeout=8, verify=False)
                response_lower = response.text.lower()
                for sig in error_signatures:
                    if sig in response_lower:
                        vulnerabilities.append({
                            'name': 'SQL Injection Vulnerability',
                            'description': 'A SQL injection vulnerability was detected. An attacker could read, modify or delete database content.',
                            'severity': 'critical',
                            'owasp_category': 'A03:2021',
                            'affected_url': action,
                            'evidence': f'SQL error triggered with payload: {payload[:50]}',
                            'recommendation': 'Use parameterised queries (prepared statements) for all database operations. Never concatenate user input into SQL queries.'
                        })
                        break
            except Exception:
                pass
    return vulnerabilities


def check_auth_weaknesses(url, forms):
    vulnerabilities = []
    for form in forms:
        inputs = form.find_all('input')
        input_types = [i.get('type', '').lower() for i in inputs]
        input_names = [i.get('name', '').lower() for i in inputs]

        is_login = any(
            t in input_types for t in ['password']
        ) or any(
            n in input_names for n in ['password', 'pass', 'pwd']
        )

        if is_login:
            # Check for CSRF token
            has_csrf = any(
                'csrf' in i.get('name', '').lower()
                for i in inputs
            )
            if not has_csrf:
                vulnerabilities.append({
                    'name': 'Missing CSRF Token on Login Form',
                    'description': 'The login form does not include a CSRF token, making it vulnerable to Cross-Site Request Forgery attacks.',
                    'severity': 'high',
                    'owasp_category': 'A07:2021',
                    'affected_url': url,
                    'evidence': 'No CSRF token input found in login form',
                    'recommendation': 'Implement CSRF tokens on all forms that perform state-changing operations.'
                })

    return vulnerabilities


def run_scan(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'running'
        scan.save()

        url = scan.target.url
        all_vulnerabilities = []

        # 1. SSL check
        all_vulnerabilities += check_ssl(url)

        # 2. Security headers
        all_vulnerabilities += check_security_headers(url)

        # 3. Get page and forms
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            # 4. XSS check
            all_vulnerabilities += check_xss(url, forms)

            # 5. SQLi check
            all_vulnerabilities += check_sqli(url, forms)

            # 6. Auth weaknesses
            all_vulnerabilities += check_auth_weaknesses(url, forms)

        except Exception:
            pass

        # Save vulnerabilities
        for vuln_data in all_vulnerabilities:
            Vulnerability.objects.create(
                scan=scan,
                name=vuln_data['name'],
                description=vuln_data['description'],
                severity=vuln_data['severity'],
                owasp_category=vuln_data['owasp_category'],
                affected_url=vuln_data['affected_url'],
                evidence=vuln_data.get('evidence', ''),
                recommendation=vuln_data['recommendation'],
            )

        # Calculate score and save report
        score = calculate_score(all_vulnerabilities)
        scan.security_score = score
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()

        # Create report
        vulns = scan.vulnerabilities.all()
        Report.objects.create(
            scan=scan,
            total_vulnerabilities=vulns.count(),
            critical_count=vulns.filter(severity='critical').count(),
            high_count=vulns.filter(severity='high').count(),
            medium_count=vulns.filter(severity='medium').count(),
            low_count=vulns.filter(severity='low').count(),
        )

    except Exception as e:
        scan.status = 'failed'
        scan.save()


@login_required
def start_scan(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        url = data.get('url', '').strip()

        if not url:
            return JsonResponse({'error': 'URL is required'}, status=400)

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Create or get target
        target, created = Target.objects.get_or_create(
            url=url,
            defaults={
                'name': url,
                'target_type': data.get('target_type', 'other'),
                'added_by': request.user
            }
        )

        # Create scan
        scan = Scan.objects.create(
            target=target,
            started_by=request.user,
            status='pending'
        )

        # Run scan directly (Celery not needed for now)
        run_scan(scan.id)

        return JsonResponse({
            'scan_id': scan.id,
            'status': 'completed'
        })

    return JsonResponse({'error': 'POST required'}, status=405)


@login_required
def scan_results(request, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
        vulns = scan.vulnerabilities.all()

        return JsonResponse({
            'status': scan.status,
            'score': scan.security_score,
            'url': scan.target.url,
            'completed_at': str(scan.completed_at),
            'vulnerabilities': [
                {
                    'name': v.name,
                    'severity': v.severity,
                    'owasp': v.owasp_category,
                    'url': v.affected_url,
                    'description': v.description,
                    'recommendation': v.recommendation,
                    'evidence': v.evidence,
                    'status': v.status,
                }
                for v in vulns
            ]
        })
    except Scan.DoesNotExist:
        return JsonResponse({'error': 'Scan not found'}, status=404)


@login_required
def get_dashboard_data(request):
    scans = Scan.objects.filter(started_by=request.user).order_by('-started_at')
    from .models import Vulnerability
    all_vulns = Vulnerability.objects.filter(scan__started_by=request.user)

    return JsonResponse({
        'total_scans': scans.count(),
        'completed_scans': scans.filter(status='completed').count(),
        'total_vulnerabilities': all_vulns.count(),
        'critical': all_vulns.filter(severity='critical').count(),
        'high': all_vulns.filter(severity='high').count(),
        'medium': all_vulns.filter(severity='medium').count(),
        'low': all_vulns.filter(severity='low').count(),
        'avg_score': int(scans.filter(status='completed').values_list('security_score', flat=True).first() or 0),
        'recent_scans': [
            {
                'id': s.id,
                'url': s.target.url,
                'status': s.status,
                'score': s.security_score,
                'date': s.started_at.strftime('%d %b %Y'),
            }
            for s in scans[:10]
        ]
    })

@login_required
def all_scans(request):
    try:
        role = request.user.profile.role
    except Exception:
        role = 'it'

    if role == 'admin':
        scans = Scan.objects.all().order_by('-started_at')
    else:
        scans = Scan.objects.filter(started_by=request.user).order_by('-started_at')
    data = []
    for s in scans:
        vulns = s.vulnerabilities.all()
        data.append({
            'id': 'scan-' + str(s.id),
            'url': s.target.url,
            'depth': 'standard',
            'appType': s.target.target_type,
            'score': s.security_score,
            'criticalCount': vulns.filter(severity='critical').count(),
            'date': s.started_at.strftime('%d %b %Y, %H:%M'),
            'status': 'completed' if s.status == 'completed' else s.status,
            'vulns': [
                {
                    'vid': 'V-' + str(v.id).zfill(3),
                    'name': v.name,
                    'owasp': v.owasp_category,
                    'severity': v.severity,
                    'desc': v.description,
                    'location': v.affected_url,
                    'status': v.status,
                }
                for v in vulns
            ],
        })
    return JsonResponse({'scans': data}) 

def get_plain_language_summary(vulnerabilities, score):
    if score >= 85:
        risk_level = "Excellent"
        risk_message = "Your website is well protected with no significant issues found."
    elif score >= 70:
        risk_level = "Good"
        risk_message = "Your website is mostly secure, with a few minor improvements recommended."
    elif score >= 50:
        risk_level = "Needs Attention"
        risk_message = "Several issues were found that should be addressed soon to reduce risk."
    else:
        risk_level = "Urgent — High Risk"
        risk_message = "Serious security issues were found that need immediate attention."

    plain_descriptions = {
        'Missing HSTS Header': 'Your website does not fully enforce secure connections, which could expose visitors to certain attacks.',
        'Missing Content Security Policy': 'Your website lacks a protection that helps block malicious scripts from running.',
        'Missing X-Frame-Options': 'Your website could be embedded inside another website without permission, a technique sometimes used to trick users.',
        'Missing X-Content-Type-Options': 'Your website does not fully protect against a technique that can trick browsers into misreading files.',
        'No HTTPS Encryption': 'Your website does not use a secure connection, meaning information sent by visitors could potentially be intercepted.',
        'SSL Certificate Error': "Your website's security certificate has a problem, which can cause visitors to see security warnings or expose data to interception.",
        'Reflected XSS Vulnerability': 'A weakness was found that could let an attacker run harmful code through your website to affect visitors.',
        'SQL Injection Vulnerability': 'A serious weakness was found that could let an attacker access or damage your database.',
        'Missing CSRF Token on Login Form': 'Your login page lacks a protection against attackers tricking users into performing unwanted actions.',
    }

    plain_findings = []
    for v in vulnerabilities:
        plain_findings.append(
            plain_descriptions.get(v['name'], 'A security issue was found that should be reviewed by your IT team.')
        )

    return {
        'risk_level': risk_level,
        'risk_message': risk_message,
        'plain_findings': plain_findings,
        'recommendation': 'We recommend reviewing this report with your IT team to address these items promptly.' if vulnerabilities else 'No action is needed at this time. Continue regular monitoring.',
    }

@login_required
def executive_summary(request, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
        vulns = scan.vulnerabilities.all()
        vuln_list = [{'name': v.name} for v in vulns]
        summary = get_plain_language_summary(vuln_list, scan.security_score)

        return JsonResponse({
            'url': scan.target.url,
            'date': scan.started_at.strftime('%d %b %Y'),
            'risk_level': summary['risk_level'],
            'risk_message': summary['risk_message'],
            'plain_findings': summary['plain_findings'],
            'recommendation': summary['recommendation'],
        })
    except Scan.DoesNotExist:
        return JsonResponse({'error': 'Scan not found'}, status=404)

@login_required
def download_pdf(request, scan_id, report_type):
    try:
        scan = Scan.objects.get(id=scan_id)
        vulns = scan.vulnerabilities.all()
    except Scan.DoesNotExist:
        return HttpResponse('Scan not found', status=404)

    if report_type == 'executive':
        vuln_list = [{'name': v.name} for v in vulns]
        summary = get_plain_language_summary(vuln_list, scan.security_score)

        html = f"""
        <html><head><style>
            body {{ font-family: Helvetica, Arial, sans-serif; color: #0F172A; font-size: 12px; }}
            h1 {{ color: #1B4FD8; font-size: 22px; }}
            .meta {{ color: #64748B; font-size: 11px; margin-bottom: 16px; }}
            .risk-box {{ background-color: #EFF6FF; border-left: 4px solid #1B4FD8; padding: 12px 16px; margin-bottom: 16px; }}
            .risk-level {{ font-size: 20px; font-weight: bold; color: #1B4FD8; }}
            .risk-message {{ font-size: 12px; color: #334155; margin-top: 4px; }}
            .finding {{ margin-bottom: 8px; padding-left: 12px; }}
            .recommend {{ background-color: #F0FDF4; border-left: 4px solid #16A34A; padding: 10px 14px; margin-top: 16px; color: #14532D; }}
            footer {{ margin-top: 30px; color: #94A3B8; font-size: 9px; }}
        </style></head>
        <body>
        <h1>WebGuard Executive Summary</h1>
        <div class="meta">Target: {scan.target.url} | Date: {scan.started_at.strftime('%d %b %Y')}</div>
        <div class="risk-box">
            <div class="risk-level">{summary['risk_level']}</div>
            <div class="risk-message">{summary['risk_message']}</div>
        </div>
        <h3>Summary of Findings</h3>
        {''.join(f'<div class="finding">&bull; {f}</div>' for f in summary['plain_findings']) or '<div class="finding">No issues were found during this scan.</div>'}
        <div class="recommend">{summary['recommendation']}</div>
        <footer>Generated by WebGuard - A Caleb University Research Project - {timezone.now().strftime('%d %b %Y')}</footer>
        </body></html>
        """
    else:
        rows = ''.join(f"""
            <tr>
                <td>{v.name}</td>
                <td>{v.severity.upper()}</td>
                <td>{v.owasp_category}</td>
                <td>{v.affected_url}</td>
                <td>{v.description}</td>
            </tr>
        """ for v in vulns)

        html = f"""
        <html><head><style>
            body {{ font-family: Helvetica, Arial, sans-serif; color: #0F172A; font-size: 11px; }}
            h1 {{ color: #1B4FD8; font-size: 20px; }}
            h2 {{ color: #1B4FD8; font-size: 14px; margin-top: 18px; }}
            .meta {{ color: #64748B; font-size: 10px; margin-bottom: 14px; }}
            .score-box {{ background-color: #EFF6FF; border-left: 4px solid #1B4FD8; padding: 10px 14px; margin-bottom: 14px; }}
            .score-num {{ font-size: 28px; font-weight: bold; color: #1B4FD8; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 10px; table-layout: fixed; }}
            th {{ background-color: #1B4FD8; color: white; padding: 6px 8px; text-align: left; word-wrap: break-word; }}
            td {{ padding: 6px 8px; border-bottom: 1px solid #E2E8F0; word-wrap: break-word; word-break: break-all; }}
            footer {{ margin-top: 24px; color: #94A3B8; font-size: 9px; }}
        </style></head>
        <body>
        <h1>WebGuard Vulnerability Report</h1>
        <div class="meta">Target: {scan.target.url} | Date: {scan.started_at.strftime('%d %b %Y')} | Status: {scan.status}</div>
        <div class="score-box">
            <div>Security Score</div>
            <div class="score-num">{scan.security_score} / 100</div>
        </div>
        <h2>Summary</h2>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
            <tr><td>Total Vulnerabilities</td><td>{vulns.count()}</td></tr>
            <tr><td>Critical</td><td>{vulns.filter(severity='critical').count()}</td></tr>
            <tr><td>High</td><td>{vulns.filter(severity='high').count()}</td></tr>
            <tr><td>Medium</td><td>{vulns.filter(severity='medium').count()}</td></tr>
            <tr><td>Low</td><td>{vulns.filter(severity='low').count()}</td></tr>
        </table>
        <h2>Vulnerability Details</h2>
       <table>
            <tr>
                <th style="width:18%">Name</th>
                <th style="width:8%">Severity</th>
                <th style="width:10%">OWASP</th>
                <th style="width:24%">Location</th>
                <th style="width:40%">Description</th>
            </tr>
            {rows}
        </table>
        <footer>Generated by WebGuard - A Caleb University Research Project - {timezone.now().strftime('%d %b %Y')}</footer>
        </body></html>
        """

    result = BytesIO()
    pdf = pisa.CreatePDF(html, dest=result)

    if pdf.err:
        return HttpResponse('Error generating PDF', status=500)

    response = HttpResponse(result.getvalue(), content_type='application/pdf')
    filename = f"webguard_{report_type}_report_{scan.id}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response 

@login_required
def org_risk_summary(request):
    scans = Scan.objects.filter(status='completed').order_by('-started_at')

    if not scans.exists():
        return JsonResponse({
            'has_data': False,
        })

    total_apps = scans.count()
    avg_score = sum(s.security_score for s in scans) / total_apps

    good_count = sum(1 for s in scans if s.security_score >= 70)
    needs_attention_count = sum(1 for s in scans if 50 <= s.security_score < 70)
    urgent_count = sum(1 for s in scans if s.security_score < 50)

    if avg_score >= 85:
        overall = "Overall, the university's web applications are in excellent security standing."
    elif avg_score >= 70:
        overall = "Overall, the university's web applications are in good security standing, with minor improvements recommended."
    elif avg_score >= 50:
        overall = "Overall, several applications need attention to reduce security risk."
    else:
        overall = "Overall, urgent action is recommended — multiple applications have serious security concerns."

    recent = []
    for s in scans[:5]:
        if s.security_score >= 70:
            level = "Good"
        elif s.security_score >= 50:
            level = "Needs Attention"
        else:
            level = "Urgent"
        recent.append({
            'url': s.target.url,
            'level': level,
            'date': s.started_at.strftime('%d %b %Y'),
        })

    return JsonResponse({
        'has_data': True,
        'total_apps': total_apps,
        'overall_message': overall,
        'good_count': good_count,
        'needs_attention_count': needs_attention_count,
        'urgent_count': urgent_count,
        'recent': recent,
    })