/* تفاعلات الواجهة: القائمة، التصفية، التحقق من النماذج، الرسائل */
document.addEventListener("DOMContentLoaded", () => {
  // قائمة الهاتف
  const toggle = document.querySelector(".nav-toggle");
  const nav = document.getElementById("nav");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }

  // القوائم المنسدلة (النقر للوحة اللمس)
  const closeDropdowns = () => document.querySelectorAll(".dropdown.open").forEach(d => d.classList.remove("open"));
  document.querySelectorAll(".dropdown-btn").forEach(btn => {
    btn.addEventListener("click", e => {
      e.stopPropagation();
      const dd = btn.parentElement;
      const wasOpen = dd.classList.contains("open");
      closeDropdowns();
      dd.classList.toggle("open", !wasOpen);
      btn.setAttribute("aria-expanded", String(!wasOpen));
    });
  });
  document.addEventListener("click", closeDropdowns);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeDropdowns(); });

  // إغلاق الرسائل وإخفاء رسائل النجاح تلقائيًا
  document.querySelectorAll(".flash-close").forEach(b => b.addEventListener("click", () => b.parentElement.remove()));
  document.querySelectorAll(".flash-success").forEach(f => setTimeout(() => f.remove(), 6000));

  // رسائل التحقق بالعربية
  document.querySelectorAll("form[data-validate] input, form[data-validate] textarea").forEach(el => {
    el.addEventListener("invalid", () => {
      const v = el.validity;
      el.setCustomValidity(
        v.valueMissing ? "هذا الحقل مطلوب." :
        v.typeMismatch ? "القيمة المدخلة غير صحيحة." :
        v.tooShort ? `الحد الأدنى ${el.minLength} أحرف.` : "");
    });
    el.addEventListener("input", () => el.setCustomValidity(""));
  });

  // عدّاد الأحرف
  document.querySelectorAll("textarea[data-counter]").forEach(t => {
    const out = document.querySelector(t.dataset.counter);
    const update = () => { if (out) out.textContent = t.value.length; };
    t.addEventListener("input", update);
    update();
  });

  // تأكيد الحذف
  document.querySelectorAll("form[data-confirm]").forEach(f => {
    f.addEventListener("submit", e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  // نموذج الإدارة: إخفاء المستوى للإنجازات
  const kind = document.getElementById("kind-select");
  const levelField = document.getElementById("level-field");
  if (kind && levelField) {
    const sync = () => { levelField.hidden = kind.value === "achievement"; };
    kind.addEventListener("change", sync);
    sync();
  }
});
