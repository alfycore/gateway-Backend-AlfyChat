// Backward-compat re-export — la logique est dans lb/registry.ts
export {
  lbRegistry as serviceRegistry,
  lbRegistry,
  generateServiceKey,
  hashServiceKey,
  type ServiceType,
  type ServiceMetrics,
  type ServiceEntry as ServiceInstance,
  type ServiceStatus,
} from '../lb/registry';
