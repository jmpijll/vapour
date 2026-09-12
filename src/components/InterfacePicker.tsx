import { useEffect, useRef, useState } from "react";
import { Check, ChevronUp, Wifi, Globe } from "lucide-react";
import type { InterfaceInfo } from "../types";
export function InterfacePicker({
  interfaces,
  value,
  onChange,
}: {
  interfaces: InterfaceInfo[];
  value: string;
  onChange: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null),
    trigger = useRef<HTMLButtonElement>(null);
  const options = [
    { id: "all", alias: "All interfaces", name: "" },
    ...interfaces,
  ];
  const selected = options.find((i) => i.id === value);
  useEffect(() => {
    const outside = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", outside);
    return () => document.removeEventListener("pointerdown", outside);
  }, []);
  return (
    <div
      className="interface-picker"
      ref={root}
      onKeyDown={(e) => {
        if (e.key === "Escape" && open) {
          e.stopPropagation();
          setOpen(false);
          trigger.current?.focus();
        }
        if (["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) {
          e.preventDefault();
          setOpen(true);
          requestAnimationFrame(() => {
            const buttons = Array.from(
              root.current?.querySelectorAll<HTMLButtonElement>(
                "[role=menuitemradio]",
              ) || [],
            );
            const index = buttons.indexOf(
              document.activeElement as HTMLButtonElement,
            );
            const next =
              e.key === "Home"
                ? 0
                : e.key === "End"
                  ? buttons.length - 1
                  : (index + (e.key === "ArrowUp" ? -1 : 1) + buttons.length) %
                    buttons.length;
            buttons[next]?.focus();
          });
        }
      }}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget)) setOpen(false);
      }}
    >
      <button
        ref={trigger}
        className="interface-trigger"
        aria-label="Network interface"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {value === "all" ? <Globe size={14} /> : <Wifi size={14} />}
        <span>{selected?.alias || selected?.name || "Unavailable"}</span>
        <ChevronUp size={13} />
      </button>
      {open && (
        <div
          className="interface-menu"
          role="menu"
          aria-label="Network interface"
        >
          {options.map((i) => (
            <button
              key={i.id}
              role="menuitemradio"
              aria-checked={value === i.id}
              onClick={() => {
                onChange(i.id);
                setOpen(false);
                trigger.current?.focus();
              }}
            >
              <span>{i.alias || i.name}</span>
              {value === i.id && <Check size={14} />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
