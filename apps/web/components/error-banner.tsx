/** A failed call, shown where the result would be. Renders nothing without a message. */
export function ErrorBanner({ message }: { message: string | null }) {
  if (message === null) return null;
  return (
    <div role="alert" className="text-red-700">
      {message}
    </div>
  );
}
