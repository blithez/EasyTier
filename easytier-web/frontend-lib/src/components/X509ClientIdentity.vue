<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { Button } from 'primevue'
import { useI18n } from 'vue-i18n'
import type { SecureModeConfig } from '../types/network'
import { readX509Pem, validateX509Pem, X509ImportError, type X509PemKind } from '../modules/x509'

const props = defineProps<{ modelValue?: SecureModeConfig }>()
const emit = defineEmits<{
  'update:modelValue': [value: SecureModeConfig | undefined]
  invalid: [value: boolean]
}>()
const { t } = useI18n()
const certificateInput = ref<HTMLInputElement>()
const privateKeyInput = ref<HTMLInputElement>()
const busy = ref(false)
const importError = ref('')
let revision = 0

const hasCertificate = computed(() => !!props.modelValue?.x509?.client_certificate_pem)
const hasPrivateKey = computed(() => !!props.modelValue?.x509?.client_private_key_pem)
const validationError = computed(() => {
  if (!hasCertificate.value && !hasPrivateKey.value) return ''
  if (!hasCertificate.value || !hasPrivateKey.value) return 'x509_pair_required'
  try {
    validateX509Pem(props.modelValue!.x509!.client_certificate_pem!, 'certificate')
    validateX509Pem(props.modelValue!.x509!.client_private_key_pem!, 'private-key')
  } catch (error) {
    return error instanceof X509ImportError ? error.translationKey : 'x509_read_failed'
  }
  return props.modelValue?.enabled ? '' : 'x509_secure_mode_required'
})
watch([validationError, busy], () => emit('invalid', !!validationError.value || busy.value), { immediate: true })
watch(() => props.modelValue, () => { importError.value = '' })
onBeforeUnmount(() => { revision++ })

async function importFile(event: Event, kind: X509PemKind) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = '' // Allow retrying the same file after a failed import.
  if (!file || busy.value) return
  const previousConfig = props.modelValue
  const currentRevision = ++revision
  busy.value = true
  importError.value = ''
  try {
    const pem = await readX509Pem(file, kind)
    // A network switch or an external config update must not receive a stale import.
    if (currentRevision !== revision || props.modelValue !== previousConfig) return
    emit('update:modelValue', {
      ...props.modelValue,
      enabled: true,
      x509: {
        trusted_client_ca_pem: [],
        client_crl_pem: [],
        ...props.modelValue?.x509,
        [kind === 'certificate' ? 'client_certificate_pem' : 'client_private_key_pem']: pem,
      },
    })
  } catch (error) {
    if (currentRevision === revision && props.modelValue === previousConfig) {
      importError.value = error instanceof X509ImportError ? error.translationKey : 'x509_read_failed'
    }
  } finally {
    if (currentRevision === revision) busy.value = false
  }
}

function removeIdentity() {
  revision++
  importError.value = ''
  const secure = props.modelValue
  if (!secure?.x509) return
  const policy = { ...secure.x509 }
  delete policy.client_certificate_pem
  delete policy.client_private_key_pem
  emit('update:modelValue', {
    ...secure,
    x509: policy.trusted_client_ca_pem?.length || policy.client_crl_pem?.length ? policy : undefined,
  })
}
</script>

<template>
  <details class="rounded border border-surface-300 p-3" :open="hasCertificate || hasPrivateKey">
    <summary class="cursor-pointer font-medium">{{ t('x509_client_auth') }}</summary>
    <div class="flex flex-col gap-3 mt-3">
      <p class="text-sm m-0">{{ t('x509_client_auth_help') }}</p>
      <div class="flex flex-wrap items-center gap-2">
        <Button type="button" :label="t('x509_import_certificate')" icon="pi pi-upload" :disabled="busy"
          @click="certificateInput?.click()" />
        <span role="status" data-testid="x509-certificate-status">{{ t(hasCertificate ? 'x509_configured' : 'x509_not_configured') }}</span>
        <input ref="certificateInput" type="file" class="hidden" :aria-label="t('x509_import_certificate')"
          data-testid="x509-certificate-file" :disabled="busy" @change="importFile($event, 'certificate')" />
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <Button type="button" :label="t('x509_import_private_key')" icon="pi pi-key" :disabled="busy"
          @click="privateKeyInput?.click()" />
        <span role="status" data-testid="x509-private-key-status">{{ t(hasPrivateKey ? 'x509_configured' : 'x509_not_configured') }}</span>
        <input ref="privateKeyInput" type="file" class="hidden" :aria-label="t('x509_import_private_key')"
          data-testid="x509-private-key-file" :disabled="busy" @change="importFile($event, 'private-key')" />
      </div>
      <p v-if="importError || validationError" role="alert" class="text-sm text-red-600 m-0">{{ t(importError || validationError) }}</p>
      <small>{{ t('x509_private_key_storage') }}</small>
      <Button v-if="hasCertificate || hasPrivateKey" type="button" :label="t('x509_remove_identity')" severity="secondary"
        outlined class="self-start" :disabled="busy" @click="removeIdentity" />
    </div>
  </details>
</template>
