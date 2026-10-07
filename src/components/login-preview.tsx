"use client";

import Image from "next/image";
import { useEffect, useRef, useState } from "react";

function BrowserArtwork() {
  return <div className="login-browser-artwork">
    <div className="login-browser-body">
      <Image src="/login/dashboard.png" alt="" width={1904} height={913} sizes="(max-width: 800px) 1px, 1800px" />
    </div>
    <div className="login-browser-toolbar">
      <img className="login-browser-lights" src="/login/traffic-lights.svg" alt="" />
      <img className="login-browser-sidebar" src="/login/sidebar.svg" alt="" />
      <div className="login-browser-navigation">
        <img src="/login/toolbar-5.svg" alt="" /><img src="/login/toolbar-6.svg" alt="" />
      </div>
      <div className="login-browser-address">
        <img src="/login/privacy.svg" alt="" />
        <div className="login-browser-url"><span><img src="/login/lock.svg" alt="" />piervuln.com</span><img src="/login/reload.svg" alt="" /></div>
      </div>
      <div className="login-browser-actions">
        {[1, 2, 3, 4].map((item) => <img key={item} src={`/login/toolbar-${item}.svg`} alt="" />)}
      </div>
    </div>
  </div>;
}

export function LoginPreview() {
  const viewport = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(1);

  useEffect(() => {
    const element = viewport.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setScale(entry.contentRect.width / 890.809));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return <div className="login-preview" ref={viewport} aria-hidden="true">
    <div className="login-preview-scene" style={{ transform: `scale(${scale})` }}>
      <div className="login-preview-glow"><BrowserArtwork /></div>
      <BrowserArtwork />
    </div>
  </div>;
}
