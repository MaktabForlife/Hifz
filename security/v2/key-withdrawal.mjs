export function withdrawalFields(purpose){
 return purpose==='academy-shared-access'
  ? {revision:'sharedAcademyRegistryRevision',withdrawn:'withdrawnSharedAcademyKids'}
  : {revision:'handoffRegistryRevision',withdrawn:'withdrawnHandoffKids'};
}

export function coversKeyWithdrawal(projection,target){
 const fields=withdrawalFields(target.purpose);
 return projection[fields.revision]>=target.registryRevision&&projection[fields.withdrawn]?.includes(target.kid);
}
