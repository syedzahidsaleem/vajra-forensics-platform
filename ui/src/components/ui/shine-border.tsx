"use client"
import React from "react"
import { cn } from "@/lib/utils"

interface ShineBorderProps {
  borderRadius?: number
  borderWidth?: number
  duration?: number
  color?: string | string[]
  className?: string
  children: React.ReactNode
}

export function ShineBorder({
  borderRadius = 12,
  borderWidth = 1,
  duration = 14,
  color = "var(--primary)",
  className,
  children,
}: ShineBorderProps) {
  return (
    <div
      style={{ "--border-radius": `${borderRadius}px` } as React.CSSProperties}
      className={cn(
        "relative rounded-[--border-radius] bg-[var(--surface)] text-[var(--text)]",
        className,
      )}
    >
      <div
        style={{
          "--border-width": `${borderWidth}px`,
          "--border-radius": `${borderRadius}px`,
          "--duration": `${duration}s`,
          "--mask-linear-gradient": `linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)`,
          "--background-radial-gradient": `radial-gradient(transparent,transparent, ${
            color instanceof Array ? color.join(",") : color
          },transparent,transparent)`,
        } as React.CSSProperties}
        className={`pointer-events-none before:pointer-events-none before:absolute before:inset-0 before:size-full before:rounded-[--border-radius] before:p-[--border-width] before:will-change-[background-position] before:content-[""] before:![-webkit-mask-composite:xor] before:![mask-composite:exclude] before:[background-image:var(--background-radial-gradient)] before:[background-size:300%_300%] before:[mask:var(--mask-linear-gradient)] before:[-webkit-mask:var(--mask-linear-gradient)] motion-safe:before:animate-shine`}
      ></div>
      {children}
    </div>
  )
}
