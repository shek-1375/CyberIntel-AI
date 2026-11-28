import { useEffect, useState } from "react";

// A tiny hash router: "#/cve/CVE-2023-34362" -> { page: "cve", param: "CVE-2023-34362" }.
// Using the URL hash means links can be bookmarked and the browser Back button works,
// without adding a routing library.
function parse() {
  const [, page = "ask", param = ""] = window.location.hash.split("/");
  return { page, param: decodeURIComponent(param) };
}

export function useRoute() {
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const onChange = () => setRoute(parse());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export function go(page, param = "") {
  window.location.hash = param ? `/${page}/${encodeURIComponent(param)}` : `/${page}`;
}
