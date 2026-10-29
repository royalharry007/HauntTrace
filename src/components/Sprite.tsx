// Hand-drawn 16×16 pixel sprites. Each character is one pixel:
// . clear · O outline · W sheet · E eye · P pupil/glint · M mouth · R tongue · L lantern · G glow

export type SpiritKind = "guardian" | "poltergeist" | "banshee" | "glutton" | "revenant" | "lingerer" | "shade";

const BOTTOM = [".OWWWWWWWWWWWWO.", ".OWWO.OWWO.OWWO.", "..OO...OO...OO.."];
const TOP = ["................", ".....OOOOOO.....", "...OOWWWWWWOO...", "..OWWWWWWWWWWO..", ".OWWWWWWWWWWWWO."];

/** Face rows 5–12 for each spirit; top and scalloped hem are shared. */
const FACES: Record<SpiritKind, string[]> = {
  guardian: [
    ".OWWEEWWWWEEWWO.",
    ".OWWEPWWWWEPWWO.",
    ".OWWEEWWWWEEWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWMWWWWMWWWO.",
    ".OWWWWMMMMWWWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWWWWWWWWWWO.",
  ],
  poltergeist: [
    ".OWEEWWWWWWEEWO.",
    ".OWWEEWWWWEEWWO.",
    ".OWWEPWWWWPEWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWMWMWMWMWMWO.",
    ".OWWWMWMWMWMWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWWWWWWWWWWO.",
  ],
  banshee: [
    ".OWWEEWWWWEEWWO.",
    ".OWWEPWWWWEPWWO.",
    ".OWWEEWWWWEEWWO.",
    ".OWWWWWMMWWWWWO.",
    ".OWWWWMMMMWWWWO.",
    ".OWWWWMMMMWWWWO.",
    ".OWWWWWMMWWWWWO.",
    ".OWWWWWWWWWWWWO.",
  ],
  glutton: [
    ".OWWWWWWWWWWWWO.",
    ".OWWEPWWWWEPWWO.",
    ".OWWEEWWWWEEWWO.",
    ".OWMMMMMMMMMMWO.",
    ".OWMMRRRRRRMMWO.",
    ".OWWMMRRRRMMWWO.",
    ".OWWWMMMMMMWWWO.",
    ".OWWWWWWWWWWWWO.",
  ],
  revenant: [
    ".OWEEEWWWWEEEWO.",
    ".OWEEEWWWWEEEWO.",
    ".OWEEEWWWWEEEWO.",
    ".OWWWWWEEWWWWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWMWMWMWMWWWO.",
    ".OWWWMMMMMMWWWO.",
    ".OWWWWWWWWWWWWO.",
  ],
  shade: [
    ".OWWWWWWWWWWWWO.",
    ".OWWEEWWWWEEWWO.",
    ".OWWEPWWWWEPWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWMMMMMMWWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWWWWWWWWWWO.",
  ],
  lingerer: [
    ".OWWWWWWWWWWWWO.",
    ".OWWEEWWWWEEWWO.",
    ".OWWPPWWWWPPWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWWMMMMWWWWO.",
    ".OWWWWWWWWWWWWO.",
    ".OWWWWWWWWWWWWO.",
  ],
};

const SLEEPY = [
  ".OWWWWWWWWWWWWO.",
  ".OWWEEWWWWEEWWO.",
  ".OWWWWWWWWWWWWO.",
  ".OWWWWWWWWWWWWO.",
  ".OWWWWWMMWWWWWO.",
  ".OWWWWWWWWWWWWO.",
  ".OWWWWWWWWWWWWO.",
  ".OWWWWWWWWWWWWO.",
];

export const PALETTES: Record<SpiritKind, Record<string, string>> = {
  guardian: { O: "#2b2433", W: "#efe9d8", E: "#1d1824", P: "#62e0e8", M: "#1d1824" },
  poltergeist: { O: "#3a1514", W: "#e0533f", E: "#2a0d0b", P: "#ffd24a", M: "#2a0d0b" },
  banshee: { O: "#1b2b3d", W: "#a9d7f5", E: "#152131", P: "#ffffff", M: "#152131" },
  glutton: { O: "#1d3317", W: "#79c95c", E: "#13240f", P: "#ffffff", M: "#13240f", R: "#e2617a" },
  revenant: { O: "#2e2a24", W: "#c9c0aa", E: "#191612", P: "#191612", M: "#191612" },
  shade: { O: "#1c2230", W: "#7f8ba3", E: "#10141c", P: "#cfd8ea", M: "#10141c" },
  lingerer: { O: "#123430", W: "#4fb5a2", E: "#0c2421", P: "#0c2421", M: "#0c2421" },
};

/** What each bad spirit means, in one plain line. */
export const SPIRITS: Record<string, { kind: SpiritKind; name: string; habit: string }> = {
  sustained_cpu: { kind: "poltergeist", name: "Poltergeist", habit: "won't stop rattling the CPU" },
  repeated_spikes: { kind: "banshee", name: "Banshee", habit: "screams in sudden CPU bursts" },
  memory_growth: { kind: "glutton", name: "Glutton", habit: "keeps eating memory" },
  repeated_restarts: { kind: "revenant", name: "Revenant", habit: "dies and keeps coming back" },
  lingering: { kind: "lingerer", name: "Lingerer", habit: "has been busy for hours and won't leave" },
  summoned: { kind: "shade", name: "Shade", habit: "stood out when you swept the house" },
};

export function spiritFor(rule: string) {
  return SPIRITS[rule] ?? { kind: "revenant" as SpiritKind, name: "Spirit", habit: "is acting oddly" };
}

export function Sprite({ kind, size = 64, sleepy, lantern, className, title }: { kind: SpiritKind; size?: number; sleepy?: boolean; lantern?: boolean; className?: string; title?: string }) {
  const rows = [...TOP, ...(sleepy ? SLEEPY : FACES[kind]), ...BOTTOM];
  const pal = PALETTES[kind];
  const rects: JSX.Element[] = [];
  rows.forEach((row, y) =>
    [...row].forEach((c, x) => {
      const fill = pal[c];
      if (fill) rects.push(<rect key={`${x}-${y}`} x={x} y={y} width={1.02} height={1.02} fill={fill} />);
    }),
  );
  return (
    <svg className={`sprite ${className ?? ""}`} width={size} height={size} viewBox={lantern ? "0 0 22 16" : "0 0 16 16"} style={lantern ? { width: (size * 22) / 16 } : undefined} shapeRendering="crispEdges" role={title ? "img" : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      {rects}
      {lantern && (
        <g className="lantern">
          <rect x={16} y={8} width={1} height={2} fill="#2b2433" />
          <rect x={16} y={9} width={3} height={1} fill="#2b2433" />
          <rect x={18} y={10} width={3} height={1} fill="#2b2433" />
          <rect x={18} y={11} width={3} height={3} fill="#ffcf4d" />
          <rect x={19} y={12} width={1} height={1} fill="#fff4c2" />
          <rect x={18} y={14} width={3} height={1} fill="#2b2433" />
        </g>
      )}
    </svg>
  );
}
