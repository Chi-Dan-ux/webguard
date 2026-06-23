// ═══════════════════════════════════════════
//  WEBGUARD — main.js
// ═══════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {

  // ── Navbar: add shadow on scroll ──────────
  const navbar = document.querySelector('.wg-navbar');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
      navbar.style.boxShadow = '0 2px 20px rgba(0,0,0,0.08)';
    } else {
      navbar.style.boxShadow = 'none';
    }
  });

  // ── Sidebar item click (mockup interaction) ──
  document.querySelectorAll('.wg-sidebar-item').forEach(item => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.wg-sidebar-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
    });
  });

  // ── Scroll reveal animations ───────────────
  const revealEls = document.querySelectorAll(
    '.wg-feature-card, .wg-step-card, .wg-vuln-card'
  );

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry, index) => {
      if (entry.isIntersecting) {
        setTimeout(() => {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
        }, index * 80);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  revealEls.forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    observer.observe(el);
  });

  // ── Smooth scroll for nav links ────────────
  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', e => {
      const target = document.querySelector(link.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        // Close mobile nav if open
        const nav = document.getElementById('navMenu');
        if (nav.classList.contains('show')) {
          nav.classList.remove('show');
        }
      }
    });
  });

  // ── Mini bar hover highlight ───────────────
  document.querySelectorAll('.wg-mini-bars span').forEach(bar => {
    bar.addEventListener('mouseenter', () => {
      bar.style.background = 'var(--blue)';
    });
    bar.addEventListener('mouseleave', (e) => {
      const bars = document.querySelectorAll('.wg-mini-bars span');
      const lastBar = bars[bars.length - 1];
      if (bar !== lastBar) {
        bar.style.background = 'var(--blue-mid)';
      }
    });
  });

  // ── Progress bar animation on load ────────
  const progressFill = document.querySelector('.wg-progress-fill');
  if (progressFill) {
    progressFill.style.width = '0%';
    setTimeout(() => {
      progressFill.style.transition = 'width 1.4s ease';
      progressFill.style.width = '72%';
    }, 600);
  }

});