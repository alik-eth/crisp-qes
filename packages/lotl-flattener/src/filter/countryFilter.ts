export function filterServicesByCountry<T extends { territory?: string }>(
  services: readonly T[],
  iso: string,
): T[] {
  const needle = iso.toUpperCase();
  const out = services.filter((s) => (s.territory ?? "").toUpperCase() === needle);
  if (out.length === 0) {
    throw new Error(`no trusted services found for country code '${iso}'`);
  }
  return out;
}
