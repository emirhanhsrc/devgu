import DOMPurify from "dompurify";

// Untrusted sources that are neutralized before reaching a sink. DEVGU must stay silent.
export function showGreeting() {
  const name = new URLSearchParams(location.search).get("name");
  document.getElementById("greeting").innerHTML = DOMPurify.sanitize(`<h1>Hello ${name}</h1>`);
  document.getElementById("title").textContent = name;
}

export function goNext() {
  const page = Number(new URLSearchParams(location.search).get("page"));
  window.location.href = "/list?page=" + encodeURIComponent(page);
}

export function Search() {
  const [sp] = useSearchParams();
  return <div>{sp.get("q")}</div>;
}
