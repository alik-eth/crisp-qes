import { useMemo, useState } from "react";
import { geoConicEqualArea, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { Feature, MultiPolygon, Polygon } from "geojson";
import worldTopo from "world-atlas/countries-110m.json";
import { QTSP_DATA, type QtspCountryData } from "../generated/qtsp-counts.js";

const NUMERIC_TO_ALPHA2: Record<string, string> = {
    "040": "AT", "056": "BE", "100": "BG", "196": "CY", "203": "CZ",
    "208": "DK", "233": "EE", "276": "DE", "300": "GR",
    "352": "IS", "372": "IE", "380": "IT", "428": "LV", "438": "LI",
    "440": "LT", "442": "LU", "470": "MT", "528": "NL", "578": "NO",
    "616": "PL", "620": "PT", "642": "RO", "703": "SK", "705": "SI",
    "724": "ES", "752": "SE", "246": "FI", "250": "FR", "191": "HR",
    "348": "HU", "804": "UA",
};

const SUPPORTED = new Set(Object.values(NUMERIC_TO_ALPHA2));
const LIVE = new Set(["UA"]);
const QTSP_BY_CODE = new Map(QTSP_DATA.map((d) => [d.code, d]));

function normaliseId(id: string | number | undefined): string {
    if (id === undefined) return "";
    const s = String(id);
    return s.length < 3 ? s.padStart(3, "0") : s;
}

const FR_BBOX: [number, number, number, number] = [-5.5, 41, 10, 51.5];
const NO_BBOX: [number, number, number, number] = [3, 57, 32, 72];

function clipToBbox(
    geom: Polygon | MultiPolygon,
    bbox: [number, number, number, number],
): Polygon | MultiPolygon {
    if (geom.type === "Polygon") {
        const c = centroid(geom.coordinates[0] ?? []);
        return inBox(c, bbox) ? geom : { ...geom, coordinates: [] };
    }
    const kept = geom.coordinates.filter((poly: number[][][]) => {
        const c = centroid(poly[0] ?? []);
        return inBox(c, bbox);
    });
    return { ...geom, coordinates: kept };
}

function centroid(ring: ReadonlyArray<readonly number[]>): [number, number] {
    let lon = 0, lat = 0, n = 0;
    for (const pt of ring) {
        if (pt.length < 2) continue;
        lon += pt[0]!; lat += pt[1]!; n++;
    }
    return n === 0 ? [NaN, NaN] : [lon / n, lat / n];
}

function inBox(c: [number, number], b: [number, number, number, number]) {
    return c[0] >= b[0] && c[0] <= b[2] && c[1] >= b[1] && c[1] <= b[3];
}

const CRIMEA_BBOX: [number, number, number, number] = [32.0, 44.0, 37.0, 46.5];

function ringFits(ring: ReadonlyArray<readonly number[]>, bbox: [number, number, number, number]) {
    for (const pt of ring) {
        if (pt.length < 2) continue;
        if (pt[0]! < bbox[0] || pt[0]! > bbox[2] || pt[1]! < bbox[1] || pt[1]! > bbox[3]) return false;
    }
    return true;
}

function findCrimea(features: ReadonlyArray<Feature<Polygon | MultiPolygon>>): number[][][] | null {
    for (const f of features) {
        const polys = f.geometry.type === "MultiPolygon" ? f.geometry.coordinates : [f.geometry.coordinates];
        for (const poly of polys) {
            if (poly[0] && ringFits(poly[0], CRIMEA_BBOX)) return poly;
        }
    }
    return null;
}

export function CoverageGrid() {
    const { features, pathGen, viewBox } = useMemo(() => {
        const topo = worldTopo as unknown as Topology<{ countries: GeometryCollection }>;
        const fc = feature(topo, topo.objects.countries) as unknown as {
            features: Feature<Polygon | MultiPolygon>[];
        };
        const crimea = findCrimea(fc.features);

        const mapped = fc.features
            .map((f) => {
                const cc = NUMERIC_TO_ALPHA2[normaliseId(f.id as string | number | undefined)];
                if (!cc || !SUPPORTED.has(cc)) return null;
                let geom = f.geometry;
                if (cc === "FR") geom = clipToBbox(geom, FR_BBOX);
                else if (cc === "NO") geom = clipToBbox(geom, NO_BBOX);
                else if (cc === "UA" && crimea) {
                    const polys = geom.type === "MultiPolygon"
                        ? [...geom.coordinates] : [geom.coordinates];
                    polys.push(crimea);
                    geom = { type: "MultiPolygon", coordinates: polys };
                }
                return { feature: { ...f, geometry: geom }, cc };
            })
            .filter((x): x is { feature: Feature<Polygon | MultiPolygon>; cc: string } => x !== null);

        const projection = geoConicEqualArea()
            .parallels([40, 65])
            .rotate([-15, 0]);
        const collection: GeoJSON.FeatureCollection<Polygon | MultiPolygon> = {
            type: "FeatureCollection",
            features: mapped.map((x) => x.feature),
        };
        const pad = 12;
        projection.fitExtent([[pad, pad], [900 - pad, 600 - pad]], collection);
        const pg = geoPath(projection);
        const [[minX, minY], [maxX, maxY]] = pg.bounds(collection);
        const w = maxX - minX + pad * 2;
        const h = maxY - minY + pad * 2;

        return {
            features: mapped,
            pathGen: pg,
            viewBox: `${minX - pad} ${minY - pad} ${w} ${h}`,
        };
    }, []);

    const [hover, setHover] = useState<{ cc: string; x: number; y: number } | null>(null);

    return (
        <div className="coverage-map" style={{ position: "relative" }}>
            <svg
                viewBox={viewBox}
                width="100%"
                preserveAspectRatio="xMidYMid meet"
                role="img"
                aria-label="QES coverage map — EU + Ukraine"
                onMouseLeave={() => setHover(null)}
            >
                <defs>
                    <pattern id="hatch-p256" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                        <line x1="0" y1="0" x2="0" y2="4" stroke="var(--ink)" strokeWidth="0.8" />
                    </pattern>
                </defs>
                {features.map(({ feature: f, cc }) => {
                    const isLive = LIVE.has(cc);
                    const data = QTSP_BY_CODE.get(cc);
                    const hasP256 = data ? data.qtspWithP256 > 0 : false;
                    const d = pathGen(f) ?? "";
                    const c = pathGen.centroid(f);
                    return (
                        <g
                            key={cc}
                            style={{ cursor: "pointer" }}
                            onMouseEnter={(e) => setHover({ cc, x: e.clientX, y: e.clientY })}
                            onMouseMove={(e) => setHover({ cc, x: e.clientX, y: e.clientY })}
                        >
                            <path
                                d={d}
                                fill={isLive ? "var(--ink)" : hasP256 ? "url(#hatch-p256)" : "var(--line)"}
                                stroke="var(--bg)"
                                strokeWidth={1}
                            />
                            {Number.isFinite(c[0]) && (
                                <text
                                    x={c[0]}
                                    y={c[1]}
                                    textAnchor="middle"
                                    dominantBaseline="central"
                                    fontFamily="var(--mono)"
                                    fontSize="5.6"
                                    fontWeight="700"
                                    letterSpacing="0.04em"
                                    fill={isLive ? "#fff" : "var(--ink)"}
                                    style={{ pointerEvents: "none" }}
                                >
                                    {cc}
                                </text>
                            )}
                        </g>
                    );
                })}
            </svg>
            {hover && <CoverageTooltip cc={hover.cc} x={hover.x} y={hover.y} />}
        </div>
    );
}


function CoverageTooltip({ cc, x, y }: { cc: string; x: number; y: number }) {
    const data = QTSP_BY_CODE.get(cc);
    const isLive = LIVE.has(cc);
    const flipLeft = typeof window !== "undefined" && x > window.innerWidth - 260;

    return (
        <div
            className="coverage-tooltip"
            style={{
                position: "fixed",
                left: flipLeft ? x - 250 : x + 16,
                top: Math.max(8, y - 8),
            }}
        >
            <div className="coverage-tooltip__head">
                <span className="coverage-tooltip__cc">{cc}</span>
                <span className="coverage-tooltip__name">{data?.name ?? cc}</span>
            </div>
            <div
                className="coverage-tooltip__status"
                style={{ color: isLive ? "var(--ink)" : "var(--muted)" }}
            >
                {isLive ? "● LIVE" : "● eIDAS READY"}
            </div>
            {data ? (
                <div className="coverage-tooltip__grid">
                    <span className="coverage-tooltip__label">QTSPs</span>
                    <span className="coverage-tooltip__val">{data.totalQtsps}</span>
                    <span className="coverage-tooltip__label">ECDSA P-256</span>
                    <span className="coverage-tooltip__val">{data.qtspWithP256}</span>
                    <span className="coverage-tooltip__label">RSA</span>
                    <span className="coverage-tooltip__val">{data.qtspWithRsa}</span>
                </div>
            ) : (
                <div className="coverage-tooltip__grid">
                    <span className="coverage-tooltip__label">QTSPs</span>
                    <span className="coverage-tooltip__val">—</span>
                </div>
            )}
        </div>
    );
}
