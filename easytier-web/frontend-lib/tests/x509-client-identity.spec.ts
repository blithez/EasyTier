import { readFileSync } from 'node:fs'
import { mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import X509ClientIdentity from '../src/components/X509ClientIdentity.vue'
import type { SecureModeConfig } from '../src/types/network'
import * as x509 from '../src/modules/x509'

const certificate = readFileSync(new URL('../../../easytier-core/tests/data/x509/client.pem', import.meta.url), 'utf8')
const privateKey = readFileSync(new URL('../../../easytier-core/tests/data/x509/client.key.pem', import.meta.url), 'utf8')
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
afterEach(() => vi.restoreAllMocks())

const Button = defineComponent({
  props: { label: String, disabled: Boolean },
  emits: ['click'],
  setup(props, { emit }) {
    return () => h('button', {
      type: 'button', disabled: props.disabled, 'data-label': props.label,
      onClick: () => emit('click'),
    }, props.label)
  },
})

function mountIdentity(initial?: SecureModeConfig) {
  let value = initial
  const wrapper = mount(X509ClientIdentity, {
    props: {
      modelValue: initial,
      'onUpdate:modelValue': (updated) => {
        value = updated
        void wrapper.setProps({ modelValue: updated })
      },
    },
    global: { stubs: { Button } },
  })
  async function select(kind: 'certificate' | 'private-key', text: string) {
    const input = wrapper.get(`[data-testid="x509-${kind}-file"]`)
    Object.defineProperty(input.element, 'files', {
      value: [new File([text], `${kind}.pem`)], configurable: true,
    })
    await input.trigger('change')
    await vi.waitFor(() => expect((input.element as HTMLInputElement).disabled).toBe(false))
  }
  return { wrapper, select, config: () => value }
}

function identity(): SecureModeConfig {
  return {
    enabled: true,
    x509: {
      trusted_client_ca_pem: ['preserved-ca'], client_crl_pem: ['preserved-crl'],
      client_certificate_pem: certificate, client_private_key_pem: privateKey,
    },
  }
}

describe('X.509 client identity controls', () => {
  it('imports a pair, enables secure mode, and never renders private key material', async () => {
    const { wrapper, select, config } = mountIdentity()
    await select('certificate', certificate)
    expect(config()?.enabled).toBe(true)
    expect(wrapper.get('[role="alert"]').text()).toBe('x509_pair_required')
    expect(wrapper.emitted('invalid')?.at(-1)).toEqual([true])
    await select('private-key', privateKey)
    expect(config()?.x509?.client_private_key_pem).toBe(privateKey)
    expect(config()?.x509?.client_certificate_pem).toBe(certificate)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
    expect(wrapper.emitted('invalid')?.at(-1)).toEqual([false])
    expect(wrapper.html()).not.toContain(privateKey.split('\n')[1])
    wrapper.unmount()
  })

  it('preserves the existing identity after a failed replacement and clears only the client identity', async () => {
    const { wrapper, select, config } = mountIdentity(identity())
    await select('certificate', 'not a PEM certificate')
    expect(config()?.x509?.client_certificate_pem).toBe(certificate)
    expect(wrapper.get('[role="alert"]').text()).toBe('x509_invalid_certificate')
    await wrapper.get('[data-label="x509_remove_identity"]').trigger('click')
    expect(config()?.x509).toEqual({ trusted_client_ca_pem: ['preserved-ca'], client_crl_pem: ['preserved-crl'] })
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('does not apply an import to a different network configuration', async () => {
    let finish!: (pem: string) => void
    vi.spyOn(x509, 'readX509Pem').mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    const { wrapper } = mountIdentity()
    const input = wrapper.get('[data-testid="x509-certificate-file"]')
    Object.defineProperty(input.element, 'files', { value: [new File([certificate], 'client.pem')] })
    await input.trigger('change')
    await wrapper.setProps({ modelValue: { enabled: true, local_private_key: 'different-network-key' } })
    finish(certificate)
    await vi.waitFor(() => expect((input.element as HTMLInputElement).disabled).toBe(false))
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    wrapper.unmount()
  })
})
