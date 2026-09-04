'use client';
import React from 'react';
import { motion } from 'framer-motion';

type GradientDotsProps = React.ComponentProps<typeof motion.div> & {
  dotSize?: number;
  spacing?: number;
  duration?: number;
  colorCycleDuration?: number;
  backgroundColor?: string;
};

export function GradientDots({
  dotSize = 6,
  spacing = 28,
  duration = 60,
  colorCycleDuration = 12,
  backgroundColor = 'transparent',
  className,
  ...props
}: GradientDotsProps) {
  const hexSpacing = spacing * 1.732;

  return (
    <motion.div
      className={`absolute inset-0 pointer-events-none ${className ?? ''}`}
      style={{
        backgroundColor,
        backgroundImage: `
          radial-gradient(circle, var(--primary) 1px, transparent 1px)
        `,
        backgroundSize: `${spacing}px ${hexSpacing}px`,
        backgroundPosition: `0px 0px`,
        opacity: 0.25,
      }}
      animate={{
        backgroundPosition: [
          `0px 0px`,
          `${spacing}px ${hexSpacing}px`,
        ],
      }}
      transition={{
        duration,
        ease: 'linear',
        repeat: Infinity,
      }}
      {...props}
    />
  );
}
