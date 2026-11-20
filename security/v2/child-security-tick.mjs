import {runtimeFor} from './runtime.mjs';
import {runtimeServices} from './runtime-service.mjs';

export const childSecurityCron = '* * * * *';
const workLimit = 10;

export function createChildSecurityTick({getRuntime = runtimeFor, getServices = runtimeServices} = {}) {
  return async function childSecurityTick(event, env, app) {
    // Background security work belongs solely to the explicitly active cutover.
    if (event.cron !== childSecurityCron ||
        env.UAA_V111_CUTOVER !== 'active' ||
        env.UAA_V2_ENABLED !== '1') return {skipped: true};
    if (app !== 'studio' && app !== 'hifz') throw Error('CHILD_SECURITY_WRONG_OWNER');
    const runtime = await getRuntime(env, {app});
    if (runtime.app !== app) throw Error('CHILD_SECURITY_WRONG_OWNER');
    const services = await getServices(runtime);
    // A transient publication error must not prevent attempting the durable
    // report queue. Only the existing signed reply path can acknowledge it.
    let publication;
    let publicationFailed = false;
    try {
      publication = await services.publishPending({limit: workLimit});
    } catch {
      publicationFailed = true;
    }
    const reports = await services.deliverReports({limit: workLimit, now: runtime.clock()});
    if (publicationFailed) throw Error('CHILD_SECURITY_PUBLICATION_RETRY_REQUIRED');
    return {publication, reports};
  };
}

export const runChildSecurityTick = createChildSecurityTick();
