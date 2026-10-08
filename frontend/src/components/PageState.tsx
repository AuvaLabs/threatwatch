import type { ComponentChildren } from "preact";

export function LoadingState({ label = "Loading intelligence" }: { label?: string }) {
  return (
    <div aria-live="polite" class="state-panel state-loading" role="status">
      <span class="loading-mark" />
      <p>{label}</p>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div class="state-panel state-error" role="alert">
      <strong>Intelligence is temporarily unavailable</strong>
      <p>{message}</p>
      <button class="button secondary" onClick={() => location.reload()} type="button">Try again</button>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children: ComponentChildren }) {
  return (
    <div class="state-panel state-empty">
      <strong>{title}</strong>
      <p>{children}</p>
    </div>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ComponentChildren;
}) {
  return (
    <header class="page-header">
      <div>
        {eyebrow && <p class="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p class="page-description">{description}</p>}
      </div>
      {actions && <div class="page-actions">{actions}</div>}
    </header>
  );
}
