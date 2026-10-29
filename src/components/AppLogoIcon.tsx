import React from 'react';

interface AppLogoIconProps {
  className?: string;
  size?: number;
}

export const AppLogoIcon: React.FC<AppLogoIconProps> = ({ className = 'w-10 h-10', size = 40 }) => {
  return (
    <div className={`relative flex items-center justify-center shrink-0 ${className}`}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="drop-shadow-[0_0_15px_rgba(6,182,212,0.4)]"
      >
        <defs>
          {/* Background Gradient */}
          <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0f172a" />
            <stop offset="50%" stopColor="#082f49" />
            <stop offset="100%" stopColor="#020617" />
          </linearGradient>

          {/* Shield Neon Cyan/Emerald Gradient */}
          <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#06b6d4" />
            <stop offset="50%" stopColor="#00f5d4" />
            <stop offset="100%" stopColor="#10b981" />
          </linearGradient>

          {/* Inner Glow Gradient */}
          <linearGradient id="innerGlow" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#34d399" stopOpacity="0.2" />
          </linearGradient>

          {/* Glow Filter */}
          <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Squircle Android/Windows App Icon Base Container */}
        <rect
          x="4"
          y="4"
          width="92"
          height="92"
          rx="24"
          fill="url(#bgGrad)"
          stroke="#1e293b"
          strokeWidth="3"
        />

        {/* Outer Glow Ring */}
        <rect
          x="8"
          y="8"
          width="84"
          height="84"
          rx="20"
          fill="none"
          stroke="url(#shieldGrad)"
          strokeWidth="1.5"
          strokeOpacity="0.3"
        />

        {/* 3D Shield Outline */}
        <path
          d="M50 18 L76 28 V52 C76 68 64 80 50 85 C36 80 24 68 24 52 V28 L50 18 Z"
          fill="url(#shieldGrad)"
          fillOpacity="0.15"
          stroke="url(#shieldGrad)"
          strokeWidth="4.5"
          strokeLinejoin="round"
          filter="url(#neonGlow)"
        />

        {/* Inner Security Core Nodes */}
        <path
          d="M50 25 L68 33 V50 C68 62 58 72 50 76 C42 72 32 62 32 50 V33 L50 25 Z"
          fill="none"
          stroke="url(#innerGlow)"
          strokeWidth="2"
          strokeDasharray="4 2"
        />

        {/* Cyber Globe Grid Latitude Arc inside Shield */}
        <path
          d="M32 50 Q50 60 68 50"
          fill="none"
          stroke="#38bdf8"
          strokeWidth="2.5"
          strokeLinecap="round"
        />
        <path
          d="M36 40 Q50 48 64 40"
          fill="none"
          stroke="#38bdf8"
          strokeWidth="2"
          strokeLinecap="round"
          strokeOpacity="0.8"
        />

        {/* Central Glowing Diamond Core */}
        <polygon
          points="50,38 58,50 50,62 42,50"
          fill="#00f5d4"
          className="animate-pulse"
        />
        <circle cx="50" cy="50" r="3" fill="#ffffff" />
      </svg>
    </div>
  );
};
