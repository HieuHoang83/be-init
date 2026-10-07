# Job System - Frontend (React + Zustand + Sonner)

## 1. Zustand Store (`jobStore.ts`)

```ts
export type JobStatus = 'idle'|'pending'|'processing'|'completed'|'error';

export interface ActiveJob {
  jobId: string;
  productCode: string;
  status: JobStatus;
  toastId: string|number|null;
  type?: 'haravan_reverse_sync';
}

isLocked: () => {
  const s = get().activeJob?.status;
  return s === 'pending' || s === 'processing';
}
```

> **Chuông (Notification Bell) KHÔNG được disable** khi `isLocked() === true`.

## 2. Toast - 1 toast duy nhất

**Tạo job:**
```ts
const toastId = toast.loading(msg, { duration: Infinity, closeButton: false });
setActiveJob({ ..., toastId });
```

**Khi terminal (update inplace):**
```ts
toast.success(msg, { id: toastId, duration: 5000, closeButton: true });
toast.error(msg, { id: toastId, duration: 5000, closeButton: true });
```

## 3. Hooks

- `useJobEvents()` – SSE `job:update`. Xử lý terminal + clear sau ~5.5s (guard jobId).
- `useJobPolling()` – Poll `/api/jobs/:id` 1.5s khi running. Terminal → update inplace + clear sau ~5.5s + stop.

## 4. ProductForm

```tsx
const { setActiveJob, isLocked } = useJobStore();
useJobEvents(); useJobPolling();

const handleReverseSync = async (payload={}) => {
  const res = await haravanReverseSync(productCode, payload);
  const toastId = toast.loading(`Đang cập nhật ngược lên Haravan: ${productCode}...`, { duration: Infinity, closeButton: false });
  setActiveJob({ jobId: res.job_id, productCode: res.product_code, status: res.status, toastId, type: 'haravan_reverse_sync' });
};

const locked = isLocked();
<button disabled={locked}>Cập nhật ngược lên Haravan</button>
// Chuông KHÔNG disabled khi locked
```

## 5. Mount global

```tsx
function JobListeners(){ useJobEvents(); useJobPolling(); return null; }
<App><JobListeners/>...</App>
```

## 6. Nguyên tắc

- **1 toast duy nhất** (loading → update inplace)
- **Unlock CHỈ dựa terminal**: clear sau ~5.5s khi nhận `completed|error` (SSE hoặc poll), guard `jobId`
- **Chuông luôn hoạt động** khi form locked
- **Realtime + fallback** đảm bảo không bỏ lỡ terminal
