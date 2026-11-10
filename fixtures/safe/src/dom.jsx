import DOMPurify from "dompurify";

// Dangerous-looking APIs that are used safely. DEVGU must stay silent here.
export function render(el, text, html) {
  el.textContent = text;
  el.innerHTML = "";
  el.innerHTML = "<hr>";
  el.innerHTML = DOMPurify.sanitize(html);
  el.insertAdjacentHTML("beforeend", "<p>static</p>");
}

export const Safe = ({ html }) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
export const Static = () => <div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />;
