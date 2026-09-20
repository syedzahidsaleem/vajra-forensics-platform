import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDevicePath(path: string | undefined | null): {
  primary: string;
  raw: string;
  driveNumber: string | null;
} {
  if (!path) {
    return { primary: 'Drive 0', raw: '\\\\.\\PhysicalDrive0', driveNumber: '0' };
  }
  const match = path.match(/PhysicalDrive(\d+)/i);
  if (match) {
    return {
      primary: `Drive ${match[1]}`,
      raw: path,
      driveNumber: match[1],
    };
  }
  const sdMatch = path.match(/\/(?:dev\/)?(sd[a-z]|nvme\d+n\d+)/i);
  if (sdMatch) {
    return {
      primary: sdMatch[1].toUpperCase(),
      raw: path,
      driveNumber: null,
    };
  }
  return {
    primary: path,
    raw: path,
    driveNumber: null,
  };
}
