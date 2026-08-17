/* drivers/snd.h — \Device\Snd*, the PCM stream devices (AUD-1, HACK-007). */
#ifndef PROSKRNL_DRIVERS_SND_H
#define PROSKRNL_DRIVERS_SND_H

/* Publish one \Device\Snd<n> per PCM stream the virtio-snd device reports
 * (drivers/virtio/snd.c); no device, no nodes — loudly. */
void SndInitialize(void);

#endif /* PROSKRNL_DRIVERS_SND_H */
