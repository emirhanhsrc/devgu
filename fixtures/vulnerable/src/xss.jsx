// Intentionally vulnerable demo code. Lines tagged "expect:" must be reported by DEVGU.
export function render(el, html, name) {
  el.innerHTML = html; // expect: JS-XSS-001
  el.outerHTML = `<b>${name}</b>`; // expect: JS-XSS-001
  el.insertAdjacentHTML("beforeend", html); // expect: JS-XSS-003
  document.write(html); // expect: JS-XSS-003
}

export const Banner = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />; // expect: JS-XSS-002
