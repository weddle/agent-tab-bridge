export function resolveCreateTargetParams(params: Record<string, unknown> | undefined) {
  const background = params?.background;
  const focus = params?.focus;
  if (background === true && focus === true) {
    throw new Error("Target.createTarget does not support background=true with focus=true");
  }
  // Only an explicitly foreground request changes the default to foreground.
  const resolvedBackground =
    focus === undefined ? background !== false : background === true && focus === false;
  return {
    background: resolvedBackground,
    focus: focus === true || (focus === undefined && !resolvedBackground),
  };
}
