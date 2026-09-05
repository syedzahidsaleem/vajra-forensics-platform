"use client"
import React from "react"
import { cn } from "@/lib/utils"

interface ShineBorderProps {
  borderRadius?: number
  borderWidth?: number
  duration?: number
  color?: string | string[]
  className?: string
  style?: React.CSSProperties
  children: React.ReactNode
  onClick?: () => void
}

export function ShineBorder({
  borderRadius = 12,
  borderWidth = 1,
  duration = 14,
  color = "var(--primary)",
  className,
  style,
  children,
  onClick,
}: ShineBorderProps) {
  return (
    <div
      onClick={onClick}
      style={{
        "--border-radius": `${borderRadius}px`,
        ...style,
      } as React.CSSProperties}
      className={cn(
        "relative rounded-[--border-radius] bg-[var(--surface)] border border-[var(--border)]/40 text-[var(--text)] w-full box-border",
        className,
      )}
    >
      <div
        style={{
          "--border-width": `${borderWidth}px`,
          "--border-radius": `${borderRadius}px`,
          "--duration": `${duration}s`,
          "--mask-linear-gradient": `linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)`,
          "--background-radial-gradient": `radial-gradient(circle at center, ${
            color instanceof Array ? color.join(",") : color
          } 0%, ${
            color instanceof Array ? color.join(",") : color
          } 25%, transparent 65%)`,
        } as React.CSSProperties}
        className={`pointer-events-none absolute inset-0 rounded-[--border-radius] overflow-hidden z-10 before:pointer-events-none before:absolute before:inset-0 before:size-full before:rounded-[--border-radius] before:p-[--border-width] before:will-change-[background-position] before:content-[""] before:![-webkit-mask-composite:xor] before:![mask-composite:exclude] before:[background-image:var(--background-radial-gradient)] before:[background-size:300%_300%] before:[mask:var(--mask-linear-gradient)] before:[-webkit-mask:var(--mask-linear-gradient)] motion-safe:before:animate-shine`}
      ></div>
      {children}
    </div>
  )
}
