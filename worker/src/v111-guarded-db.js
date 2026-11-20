// Fence each existing native effect in its owning D1 transaction. This does not
// turn a compound journal save into an atomic operation or provide a receipt.
export function guardedHifzDB(db, guard) {
  if (!db?.prepare || !db?.batch || !(typeof guard==='function'||typeof guard?.sql==='string'&&Array.isArray(guard.args))) throw Object.assign(new Error('Native write guard unavailable'), {code:'NATIVE_WRITE_GUARD_REQUIRED',status:503});
  const fenced = async items => {
    const plan=typeof guard==='function'?await guard():guard;
    if(typeof plan?.sql!=='string'||!Array.isArray(plan.args))throw Object.assign(new Error('Native write guard unavailable'),{code:'NATIVE_WRITE_GUARD_REQUIRED',status:503});
    const proof=()=>db.prepare("SELECT CASE WHEN EXISTS("+plan.sql+") THEN 1 ELSE json('UAA_V2_NATIVE_GUARD_REJECTED') END").bind(...plan.args);
    const before=Array.isArray(plan.before)?plan.before:[proof()],after=Array.isArray(plan.after)?plan.after:[];
    if(!before.length)throw new Error('Native guard is empty');
    return (await db.batch([...before,...items,...after])).slice(before.length,before.length+items.length);
  };
  const statements = new WeakMap();
  const mutates = sql => /^\s*(?:INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql);
  const wrap = (sql,args=[]) => {
    if (typeof sql !== 'string' || !/^\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql)) throw Object.assign(new Error('Unclassified native SQL'), {code:'NATIVE_SQL_NOT_CLASSIFIED',status:503});
    const stmt = db.prepare(sql).bind(...args);
    const result = {
      bind(...values) { return wrap(sql,values); },
      async first(...column) { if(mutates(sql)) throw new Error('Native mutation must use guarded run'); return stmt.first(...column); },
      async all() { if(mutates(sql)) throw new Error('Native mutation must use guarded run'); return stmt.all(); },
      async run() { return mutates(sql) ? (await fenced([stmt]))[0] : stmt.run(); }
    };
    statements.set(result,{stmt,mutation:mutates(sql)});return result;
  };
  return Object.freeze({prepare:wrap, async batch(items) {
    if(!Array.isArray(items)||items.some(s=>!statements.has(s))) throw new Error('Foreign native batch statement');
    const native=items.map(s=>statements.get(s));
    return native.some(s=>s.mutation)?fenced(native.map(s=>s.stmt)):db.batch(native.map(s=>s.stmt));
  }});
}
