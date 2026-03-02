// Deployment of sealed-secrets with leader election enabled.
// Imports the standard controller.jsonnet and overrides for HA:
// 3 replicas, leader-elect flags, POD_NAME env, and lease RBAC.

local controller = import 'controller.jsonnet';

controller {
  controller+: {
    spec+: {
      replicas: 3,
      template+: {
        spec+: {
          containers_+: {
            controller+: {
              command: [
                'controller',
                '--leader-elect',
                '--leader-elect-lease-duration=30s',
                '--leader-elect-renew-deadline=20s',
                '--leader-elect-retry-period=5s',
              ],
              env_+: {
                POD_NAME: {
                  fieldRef: { fieldPath: 'metadata.name' },
                },
              },
            },
          },
        },
      },
    },
  },

  unsealKeyRole+: {
    rules+: [
      {
        apiGroups: ['coordination.k8s.io'],
        resources: ['leases'],
        resourceNames: ['sealed-secrets-controller.bitnami.com'],
        verbs: ['get', 'update'],
      },
      {
        apiGroups: ['coordination.k8s.io'],
        resources: ['leases'],
        verbs: ['create'],
      },
    ],
  },
}
