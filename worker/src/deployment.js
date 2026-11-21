import {WorkerEntrypoint} from 'cloudflare:workers';
import {runtimeFor} from '../../security/v2/runtime.mjs';
import {runOfflineUpdateStep} from '../../security/v2/offline-operations.mjs';

export {default} from './index.js';

export class V111OfflineUpdate extends WorkerEntrypoint {
  async step(command) {
    const runtime = await runtimeFor(this.env, {app: 'hifz'});
    return runOfflineUpdateStep(runtime, command);
  }
}
