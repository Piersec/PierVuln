import Image from "next/image";
import Link from "next/link";

function BrandContent({ markSrc = "/pier-mascot-transparent.png" }: { markSrc?: string }) {
  return (
    <>
      <Image
        className="brand-mark"
        src={markSrc}
        alt=""
        width={1536}
        height={1024}
        sizes="72px"
      />
      <span aria-hidden="true">
        Pier<span className="brand-light">Vuln</span>
      </span>
    </>
  );
}

export function Brand({ href, markSrc }: { href?: string; markSrc?: string }) {
  if (href) {
    return (
      <Link className="brand" href={href} aria-label="PierVuln — início">
        <BrandContent markSrc={markSrc} />
      </Link>
    );
  }

  return (
    <span className="brand" role="img" aria-label="PierVuln">
      <BrandContent markSrc={markSrc} />
    </span>
  );
}
