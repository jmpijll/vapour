import { ArrowDown, ArrowUp } from "lucide-react";
import { formatSpeed } from "../utils/format";
export function Rate({ value, up = false }: { value: number; up?: boolean }) {
  const f = formatSpeed(value),
    Icon = up ? ArrowUp : ArrowDown;
  return (
    <div
      className="speed"
      title={up ? "Upload" : "Download"}
      aria-label={`${up ? "Upload" : "Download"} ${f.value} ${f.unit}`}
    >
      <Icon size={20} strokeWidth={1.7} />
      <div className="speed-value">
        {f.value}
        <span>{f.unit}</span>
      </div>
    </div>
  );
}
