/**
 * Run async tasks with bounded concurrency.
 * Results are returned in the same order as the input tasks.
 */
export async function runWithConcurrency<T>(
  tasks: (() => Promise<T>)[],
  limit: number,
): Promise<PromiseSettledResult<T>[]> {
  const results: PromiseSettledResult<T>[] = [];
  const executing: Set<Promise<void>> = new Set();

  for (let i = 0; i < tasks.length; i++) {
    const idx = i;
    const p = tasks[idx]()
      .then((value) => { results[idx] = { status: "fulfilled", value }; })
      .catch((reason) => { results[idx] = { status: "rejected", reason }; })
      .finally(() => { executing.delete(p); });
    executing.add(p);
    if (executing.size >= limit) await Promise.race(executing);
  }
  await Promise.all(executing);
  return results;
}
