// Untrusted data flows. The taint finding replaces the generic pattern finding on the same line.
export function showGreeting() {
  const params = new URLSearchParams(location.search);
  const name = params.get("name");
  const html = `<h1>Hello ${name}</h1>`;
  document.getElementById("greeting").innerHTML = html; // expect: JS-TAINT-001
}

export function runHash() {
  const code = location.hash.slice(1);
  eval(code); // expect: JS-TAINT-002
}

export function goNext() {
  const next = new URLSearchParams(location.search).get("next");
  window.location.href = next; // expect: JS-TAINT-003
}

window.addEventListener("message", (event) => { // expect: JS-MSG-002
  document.body.innerHTML = event.data; // expect: JS-TAINT-001
});

export function Search() {
  const [sp] = useSearchParams();
  const q = sp.get("q");
  return <div dangerouslySetInnerHTML={{ __html: q }} />; // expect: JS-TAINT-001
}
