export const STAGES = [
  { index: 0, key: 'define', label: 'Define', product: 'Aithema', summary: 'Defines the requirements baseline.' },
  { index: 1, key: 'build', label: 'Build', product: 'Paimos', summary: 'Builds PM, prototype, and staging work.' },
  { index: 2, key: 'deliver', label: 'Deliver', product: 'Pharos', summary: 'Delivers and deploys to a Pharos target.' },
  { index: 3, key: 'access', label: 'Access', product: 'Janus', summary: 'Secrets, access, and rotations.' },
];

export const ACTIONS = ['build', 'test', 'deploy', 'verify', 'janus_prepare', 'janus_apply'];

export function getStage(index) {
  return STAGES[index] ?? STAGES[0];
}

export function defaultActionForStage(stageIndex, shellState) {
  const activeOperation = shellState?.delivery?.activeOperation;
  if (stageIndex === 1) {
    return activeOperation === 'test' ? 'test' : 'build';
  }
  if (stageIndex === 2) {
    return activeOperation === 'verify' ? 'verify' : 'deploy';
  }
  if (stageIndex === 3) {
    if (activeOperation === 'janus_prepare') return 'janus_prepare';
    if (activeOperation === 'apply') return 'janus_apply';
    return shellState?.prerequisites?.pharosTarget?.readiness === 'preliminary'
      ? 'janus_prepare'
      : 'janus_apply';
  }
  return 'build';
}
