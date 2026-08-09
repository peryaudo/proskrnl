/* arch/x86_64/cpu.h — what this processor can do, as ring 3 may see it. */
#ifndef PROSKRNL_ARCH_X86_64_CPU_H
#define PROSKRNL_ARCH_X86_64_CPU_H

#include "abi/ntkeapi.h"

/* Fill KUSER_SHARED_DATA.ProcessorFeatures (PROCESSOR_FEATURE_MAX entries,
 * zeroed by the caller). This is the ONE statement of the machine's feature
 * set: everything else that answers a capability question — Wine's PE
 * RtlIsProcessorFeaturePresent, NtQuerySystemInformation's KF_* word — reads
 * it rather than re-deriving from CPUID (Art. 11). */
void KiInitializeProcessorFeatures(BOOLEAN *features);

/* The KF_* word SystemCpuInformation and SystemProcessorFeaturesInformation
 * report, composed from the array above exactly as the oracle's
 * get_cpu_features composes it from the same page. */
ULONGLONG KiProcessorFeatureBits(const BOOLEAN *features);

#endif /* PROSKRNL_ARCH_X86_64_CPU_H */
