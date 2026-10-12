export default function Skeleton({
  width = '100%', height = 14,
}: { width?: number | string; height?: number | string }) {
  return <div className="skeleton" style={{ width, height }} aria-hidden="true" />;
}
