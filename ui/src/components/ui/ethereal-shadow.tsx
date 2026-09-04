'use client';
import { useRef, useId, useEffect } from 'react';
import { animate, useMotionValue } from 'framer-motion';

interface EtherealShadowProps {
  color?: string;
  speed?: number;
  scale?: number;
  className?: string;
}

function mapRange(v: number, a: number, b: number, c: number, d: number) {
  return c + ((v - a) / (b - a)) * (d - c);
}

export function EtherealShadow({
  color = 'rgba(89,238,153,0.15)',
  speed = 60,
  scale = 40,
  className,
}: EtherealShadowProps) {
  const id = useId().replace(/:/g, '');
  const filterId = `vajra-ethereal-${id}`;
  const feRef = useRef<SVGFEColorMatrixElement>(null);
  const hue = useMotionValue(0);

  const displacement = mapRange(scale, 1, 100, 10, 60);
  const freq = mapRange(scale, 0, 100, 0.001, 0.0005);
  const duration = mapRange(speed, 1, 100, 200, 8);

  useEffect(() => {
    const ctrl = animate(hue, 360, {
      duration: duration / 25,
      repeat: Infinity,
      ease: 'linear',
      onUpdate: (v) => feRef.current?.setAttribute('values', String(v)),
    });
    return () => ctrl.stop();
  }, [duration]);

  return (
    <div
      className={`absolute inset-0 pointer-events-none overflow-hidden ${className ?? ''}`}
      aria-hidden
    >
      <svg style={{ position: 'absolute', width: 0, height: 0 }}>
        <defs>
          <filter id={filterId}>
            <feTurbulence
              type="turbulence"
              numOctaves="2"
              baseFrequency={`${freq},${freq * 4}`}
              result="undulation"
            />
            <feColorMatrix
              ref={feRef}
              in="undulation"
              type="hueRotate"
              values="0"
            />
            <feColorMatrix
              type="matrix"
              values="4 0 0 0 1  4 0 0 0 1  4 0 0 0 1  1 0 0 0 0"
              result="circulation"
            />
            <feDisplacementMap
              in="SourceGraphic"
              in2="circulation"
              scale={displacement}
              result="dist"
            />
            <feDisplacementMap
              in="dist"
              in2="undulation"
              scale={displacement}
              result="output"
            />
          </filter>
        </defs>
      </svg>
      <div
        style={{
          position: 'absolute',
          inset: -displacement,
          filter: `url(#${filterId}) blur(8px)`,
          backgroundColor: color,
          borderRadius: '50%',
          transform: 'scale(1.2)',
        }}
      />
    </div>
  );
}
