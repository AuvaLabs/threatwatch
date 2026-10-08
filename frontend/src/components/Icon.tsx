interface IconProps {
  name: "overview" | "news" | "shield" | "campaigns" | "watch" | "briefings" | "api" | "system" | "search" | "sun" | "moon" | "menu" | "close";
  size?: number;
}

const paths: Record<IconProps["name"], string[]> = {
  overview: ["M3 11.5 12 4l9 7.5", "M5 10v10h5v-6h4v6h5V10"],
  news: ["M5 4h14v16H5z", "M8 8h8", "M8 12h8", "M8 16h5"],
  shield: ["M12 3 20 6v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6z", "m9 12 2 2 4-5"],
  campaigns: ["M4 18h4V8H4z", "M10 18h4V4h-4z", "M16 18h4v-7h-4z"],
  watch: ["M12 21s7-3.6 7-10V5l-7-2-7 2v6c0 6.4 7 10 7 10Z", "M12 8v4l2 2"],
  briefings: ["M6 3h9l3 3v15H6z", "M14 3v4h4", "M9 12h6", "M9 16h6"],
  api: ["m8 8-4 4 4 4", "m16 8 4 4-4 4", "m14 5-4 14"],
  system: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z", "M4 12H2", "M22 12h-2", "m6.3 5.7-1.4 1.4", "m19.1 4.9-1.4 1.4", "M12 4V2", "M12 22v-2", "m6.3 6.3-1.4-1.4", "m19.1 19.1-1.4-1.4"],
  search: ["M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z", "m20 20-4-4"],
  sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "m17.7 17.7 1.4 1.4", "M2 12h2", "M20 12h2", "m4.9 19.1 1.4-1.4", "m17.7 6.3 1.4-1.4"],
  moon: ["M20 15.5A8.5 8.5 0 0 1 8.5 4 8.5 8.5 0 1 0 20 15.5Z"],
  menu: ["M4 7h16", "M4 12h16", "M4 17h16"],
  close: ["m6 6 12 12", "M18 6 6 18"],
};

export function Icon({ name, size = 20 }: IconProps) {
  return (
    <svg aria-hidden="true" class="icon" fill="none" height={size} viewBox="0 0 24 24" width={size}>
      {paths[name].map((path) => <path d={path} key={path} stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.7" />)}
    </svg>
  );
}
