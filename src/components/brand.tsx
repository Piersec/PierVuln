import Image from "next/image";
import Link from "next/link";

function BrandContent() {
  return (
    <>
      <Image
        className="brand-mark"
        src="/pier-mascot-transparent.png"
        alt=""
        width={1536}
        height={1024}
      />
      <span aria-hidden="true">
        Pier<span className="brand-light">Vuln</span>
      </span>
    </>
  );
}

export function Brand({ href }: { href?: string }) {
  if (href) {
    return (
      <Link className="brand" href={href} aria-label="PierVuln — início">
        <BrandContent />
      </Link>
    );
  }

  return (
    <span className="brand" role="img" aria-label="PierVuln">
      <BrandContent />
    </span>
  );
}
