export interface SystemNotificationPayload {
  title: string;
  body: string;
  threatLevel: string;
  riskScore: number;
  attackerIp?: string;
  target?: string;
  threatName?: string;
  timestamp: string;
}

// Play an authentic SOC alert ping via Web Audio API without needing external assets
export function playAlertChime(isCritical: boolean = true) {
  try {
    const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }

    const osc1 = ctx.createOscillator();
    const osc2 = ctx.createOscillator();
    const gain = ctx.createGain();

    osc1.type = isCritical ? 'triangle' : 'sine';
    osc2.type = 'sine';

    // Dual-tone security chime
    osc1.frequency.setValueAtTime(isCritical ? 880 : 587.33, ctx.currentTime);
    osc1.frequency.exponentialRampToValueAtTime(isCritical ? 523.25 : 880, ctx.currentTime + 0.28);

    osc2.frequency.setValueAtTime(isCritical ? 1318.51 : 880, ctx.currentTime);
    osc2.frequency.exponentialRampToValueAtTime(isCritical ? 659.25 : 1174.66, ctx.currentTime + 0.28);

    gain.gain.setValueAtTime(0.2, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);

    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(ctx.destination);

    osc1.start();
    osc2.start();
    osc1.stop(ctx.currentTime + 0.36);
    osc2.stop(ctx.currentTime + 0.36);
  } catch {
    // Ignore audio errors if context blocked by browser autoplay policy
  }
}

// Request and trigger Web Notifications API if available
export async function triggerWebNotification(payload: SystemNotificationPayload): Promise<{
  nativeShown: boolean;
  permission: NotificationPermission | 'unsupported';
}> {
  if (typeof window === 'undefined') {
    return { nativeShown: false, permission: 'unsupported' };
  }

  playAlertChime(payload.threatLevel === 'CRITICAL');

  if (!('Notification' in window)) {
    return { nativeShown: false, permission: 'unsupported' };
  }

  try {
    let perm = Notification.permission;
    if (perm === 'default') {
      perm = await Notification.requestPermission();
    }

    if (perm === 'granted') {
      const notif = new Notification(payload.title, {
        body: payload.body,
        icon: '/favicon.ico',
        tag: 'nebulaguard-threat-alert',
        requireInteraction: payload.threatLevel === 'CRITICAL',
      });

      notif.onclick = () => {
        window.focus();
        notif.close();
      };

      return { nativeShown: true, permission: 'granted' };
    }

    return { nativeShown: false, permission: perm };
  } catch (err) {
    console.warn('Web Notifications API call failed or sandboxed:', err);
    return { nativeShown: false, permission: (window as any).Notification?.permission || 'unsupported' };
  }
}
