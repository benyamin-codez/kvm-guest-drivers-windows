/*
 * This file contains various virtio queue related routines.
 *
 * Copyright (c) 2012-2017 Red Hat, Inc.
 *
 * Author(s):
 *  Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "trace.h"
#include "helper.h"

#if defined(EVENT_TRACING)
#include "helper.tmh"
#endif

#define SET_VA_PA() { ULONG len; va = adaptExt->indirect ? srbExt->pdesc : NULL; \
                      pa = va ? StorPortGetPhysicalAddress(DeviceExtension, NULL, va, &len).QuadPart : 0; \
                    }

VOID
SendSRB(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb,
    IN STOR_SPINLOCK LockMode
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_EXTENSION      srbExt   = NULL;
    PVOID               va = NULL;
    ULONGLONG           pa = 0;
    ULONG               QueueNumber = VIRTIO_SCSI_REQUEST_QUEUE_0;
    BOOLEAN             notify = FALSE;
    STOR_LOCK_HANDLE    LockHandle = { 0 };
    ULONG               status = STOR_STATUS_SUCCESS;
    UCHAR               ScsiStatus = SCSISTAT_GOOD;
    ULONG               MessageId;
    //ULONG               add_buffer_req_status = 0;
    int                 add_buffer_req_status = 0;
    ULONG               qty_req_vq;
    PREQUEST_LIST       element;
    ULONG               vq_req_idx;

    if (!Srb) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_WARNING, " NOT a SCSI Request Block (SRB) - !!! Potential HOST ERROR !!! ---> QEMU[pid]: kvm: virtio: zero sized buffers are not allowed\n");
        EXIT_FN_SRB();
        #endif
        return;
    }
    if (adaptExt->bRemoved) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_WARNING, " The HBA is no longer present. Setting SRB_STATUS_NO_DEVICE and completing the request.\n");
        #endif
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_NO_DEVICE);
        CompleteRequest(DeviceExtension, Srb);
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;
    }
    #if !defined(RUN_UNCHECKED)
    LOG_SRB_INFO();
    #endif
    qty_req_vq = adaptExt->num_queues;
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_VQ, " VirtIO - Total # of Queues : %lu, Request Queues : %lu \n", qty_req_vq + VIRTIO_SCSI_REQUEST_QUEUE_0, qty_req_vq);
    #endif
    if (qty_req_vq > 1) {
        STARTIO_PERFORMANCE_PARAMETERS param;
        param.Size = sizeof(STARTIO_PERFORMANCE_PARAMETERS);
        status = StorPortGetStartIoPerfParams(DeviceExtension, (PSCSI_REQUEST_BLOCK)Srb, &param);
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_MSIX, " StorPort MSI-X Vector (Perf. Param.) : %lu \n", param.MessageNumber);
        #endif
        if (status == STOR_STATUS_SUCCESS && param.MessageNumber != 0) {
            QueueNumber = MESSAGE_TO_QUEUE(param.MessageNumber);
            if (QueueNumber >= qty_req_vq + VIRTIO_SCSI_REQUEST_QUEUE_0) {
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_VQ, " Modulo assignment required for QueueNumber as it exceeds the number of virtqueues available.\n");
                #endif
                QueueNumber %= qty_req_vq;
            }
        } else {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " StorPortGetStartIoPerfParams failed srb 0x%p status 0x%x MessageNumber %d.\n", Srb, status, param.MessageNumber);
            #endif
            // FIXME
            // Should we return on this error..?
        }
    }
    else {
        QueueNumber = VIRTIO_SCSI_REQUEST_QUEUE_0;
    }

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_VQ, " Mapped VirtIO Queue : %lu \n", QueueNumber);
    #endif

    srbExt = SRB_EXTENSION(Srb);

    if (!srbExt) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " No SRB Extension on virtqueue (%lu) for SRB 0x%p \n", QueueNumber, Srb);
        EXIT_FN_SRB();
        #endif
        return;
    }

    MessageId = QUEUE_TO_MESSAGE(QueueNumber);
    vq_req_idx = QueueNumber - VIRTIO_SCSI_REQUEST_QUEUE_0;
    
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_MSIX, " StorPort MSI-X Vector (MessageId) : %lu \n", MessageId);
    if (adaptExt->num_queues > 1) {
        RhelDbgPrint(TRACE_MAPPING, " Working in VirtIO Queue %lu, i.e. Request Queue %lu (index %lu) -- in MSI-X Vector %lu -- with CPU Mask %I64d -- for SRB 0x%p \n", 
                     QueueNumber, (vq_req_idx + 1), vq_req_idx, MessageId, adaptExt->pmsg_affinity[MessageId].Mask, Srb);
    } else {
        RhelDbgPrint(TRACE_MAPPING, " Working in VirtIO Queue %lu, i.e. Request Queue %lu (index %lu) -- in MSI-X Vector %lu -- for SRB 0x%p \n", 
                     QueueNumber, (vq_req_idx + 1), vq_req_idx, MessageId, Srb);
    }
    #endif
    if (adaptExt->reset_in_progress) {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_WARNING, " Reset is in progress, completing SRB 0x%p with SRB_STATUS_BUS_RESET.\n", Srb);
        #endif
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUS_RESET);
        CompleteRequest(DeviceExtension, Srb);
        #if !defined(RUN_UNCHECKED)
        EXIT_FN_SRB();
        #endif
        return;
    }
    VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, LockMode, VIOSCSI_VQLOCKOP_LOCK);
    SET_VA_PA();
    add_buffer_req_status = virtqueue_add_buf(adaptExt->vq[QueueNumber],
        srbExt->psgl,
        srbExt->out, srbExt->in,
        &srbExt->cmd, va, pa);
    
    if (add_buffer_req_status == VQ_ADD_BUFFER_SUCCESS) {
        notify = virtqueue_kick_prepare(adaptExt->vq[QueueNumber]);
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_NOTIFY, " NOTIFY StorPort Required : %s \n", (notify) ? "YES" : "NO");
        #endif
        element = &adaptExt->processing_srbs[vq_req_idx];
        InsertTailList(&element->srb_list, &srbExt->list_entry);
        element->srb_cnt++;
    } else {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_WARNING,
            " Could not put an SRB into a VQ, so complete it with SRB_STATUS_BUSY. QueueNumber = %d, SRB = 0x%p, Lun = %d, TimeOut = %d.\n",
            QueueNumber, srbExt->Srb, SRB_LUN(Srb), Srb->TimeOutValue);
        #endif
        ScsiStatus = SCSISTAT_QUEUE_FULL;
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
        SRB_SET_SCSI_STATUS(Srb, ScsiStatus);
        StorPortBusy(DeviceExtension, 10);
        CompleteRequest(DeviceExtension, Srb);
    }
    VioScsiSpinLockManager(DeviceExtension, MessageId, &LockHandle, LockMode, VIOSCSI_VQLOCKOP_UNLOCK);
    if (notify){
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_NOTIFY, " StorPort NOTIFIED via VirtIO Queue [QueueNumber] %lu using StorPort MSI-X Vector [MessageId] %lu \n", QueueNumber, MessageId);
        #endif
        virtqueue_notify(adaptExt->vq[QueueNumber]);
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
}

BOOLEAN
SynchronizedTMFRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK Srb      = (PSCSI_REQUEST_BLOCK) Context;
    PSRB_EXTENSION      srbExt   = SRB_EXTENSION(Srb);
    PVOID               va;
    ULONGLONG           pa;

    SET_VA_PA();
    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE],
                     srbExt->psgl,
                     srbExt->out, srbExt->in,
                     &srbExt->cmd, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE]);
        #if !defined(RUN_UNCHECKED)
        EXIT_FN();
        #endif
        return TRUE;
    }
    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BUSY);
    StorPortBusy(DeviceExtension, adaptExt->queue_depth);

    #if !defined(RUN_UNCHECKED)
    EXIT_ERR();
    #endif
    return FALSE;
}

BOOLEAN
SendTMF(
    IN PVOID DeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    return StorPortSynchronizeAccess(DeviceExtension, SynchronizedTMFRoutine, (PVOID)Srb);

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

BOOLEAN
DeviceReset(
    IN PVOID DeviceExtension
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSCSI_REQUEST_BLOCK   Srb = &adaptExt->tmf_cmd.Srb;
    PSRB_EXTENSION        srbExt = adaptExt->tmf_cmd.SrbExtension;
    VirtIOSCSICmd         *cmd = &srbExt->cmd;
    ULONG                 fragLen;
    ULONG                 sgElement;

    if (adaptExt->dump_mode) {
        #if !defined(RUN_UNCHECKED)
        EXIT_FN();
        #endif
        return TRUE;
    }
    ASSERT(adaptExt->tmf_infly == FALSE);
    Srb->SrbExtension = srbExt;
    RtlZeroMemory((PVOID)cmd, sizeof(VirtIOSCSICmd));
    cmd->srb = (PVOID)Srb;
    cmd->req.tmf.lun[0] = 1;
    cmd->req.tmf.lun[1] = 0;
    cmd->req.tmf.lun[2] = 0;
    cmd->req.tmf.lun[3] = 0;
    cmd->req.tmf.type = VIRTIO_SCSI_T_TMF;
    cmd->req.tmf.subtype = VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET;
    
    srbExt->psgl = srbExt->vio_sg;
    srbExt->pdesc = srbExt->desc_alias;
    sgElement = 0;
    srbExt->psgl[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.tmf, &fragLen);
    srbExt->psgl[sgElement].length   = sizeof(cmd->req.tmf);
    sgElement++;
    srbExt->out = sgElement;
    srbExt->psgl[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.tmf, &fragLen);
    srbExt->psgl[sgElement].length = sizeof(cmd->resp.tmf);
    sgElement++;
    srbExt->in = sgElement - srbExt->out;
    StorPortPause(DeviceExtension, 60);
    if (!SendTMF(DeviceExtension, Srb)) {
        StorPortResume(DeviceExtension);
        #if !defined(RUN_UNCHECKED)
        EXIT_FN();
        #endif
        return FALSE;
    }
    adaptExt->tmf_infly = TRUE;
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return TRUE;
}

VOID
ShutDown(
    IN PVOID DeviceExtension
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    ULONG index;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    virtio_device_reset(&adaptExt->vdev);
    virtio_delete_queues(&adaptExt->vdev);
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index) {
        adaptExt->vq[index] = NULL;
    }

    virtio_device_shutdown(&adaptExt->vdev);
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

VOID
GetScsiConfig(
    IN PVOID DeviceExtension
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    adaptExt->features = virtio_get_features(&adaptExt->vdev);
    adaptExt->indirect = CHECKBIT(adaptExt->features, VIRTIO_RING_F_INDIRECT_DESC);

    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, seg_max),
                      &adaptExt->scsi_config.seg_max, sizeof(adaptExt->scsi_config.seg_max));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, num_queues),
                      &adaptExt->scsi_config.num_queues, sizeof(adaptExt->scsi_config.num_queues));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_sectors),
                      &adaptExt->scsi_config.max_sectors, sizeof(adaptExt->scsi_config.max_sectors));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, cmd_per_lun),
                      &adaptExt->scsi_config.cmd_per_lun, sizeof(adaptExt->scsi_config.cmd_per_lun));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, event_info_size),
                      &adaptExt->scsi_config.event_info_size, sizeof(adaptExt->scsi_config.event_info_size));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, sense_size),
                      &adaptExt->scsi_config.sense_size, sizeof(adaptExt->scsi_config.sense_size));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, cdb_size),
                      &adaptExt->scsi_config.cdb_size, sizeof(adaptExt->scsi_config.cdb_size));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_channel),
                      &adaptExt->scsi_config.max_channel, sizeof(adaptExt->scsi_config.max_channel));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_target),
                      &adaptExt->scsi_config.max_target, sizeof(adaptExt->scsi_config.max_target));
    virtio_get_config(&adaptExt->vdev, FIELD_OFFSET(VirtIOSCSIConfig, max_lun),
                      &adaptExt->scsi_config.max_lun, sizeof(adaptExt->scsi_config.max_lun));

    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " seg_max %lu\n", adaptExt->scsi_config.seg_max);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " max_sectors %lu\n", adaptExt->scsi_config.max_sectors);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " num_queues %lu\n", adaptExt->scsi_config.num_queues);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " cmd_per_lun %lu\n", adaptExt->scsi_config.cmd_per_lun);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " event_info_size %lu\n", adaptExt->scsi_config.event_info_size);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " sense_size %lu\n", adaptExt->scsi_config.sense_size);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " cdb_size %lu\n", adaptExt->scsi_config.cdb_size);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " max_channel %u\n", adaptExt->scsi_config.max_channel);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " max_target %u\n", adaptExt->scsi_config.max_target);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " max_lun %lu\n", adaptExt->scsi_config.max_lun);
    EXIT_FN();
    #endif
}


VOID
SetGuestFeatures(
    IN PVOID DeviceExtension
)
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    ULONGLONG          guestFeatures = 0;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    BOOLEAN            guest_flag_state = FALSE;
    BOOLEAN            packed_ring_guest_flag_state = FALSE;

    if (CHECKBIT(adaptExt->features, VIRTIO_F_VERSION_1)) {
        guestFeatures |= (1ULL << VIRTIO_F_VERSION_1);
        guest_flag_state = TRUE;
        if (CHECKBIT(adaptExt->features, VIRTIO_F_RING_PACKED)) {
            guestFeatures |= (1ULL << VIRTIO_F_RING_PACKED);
            packed_ring_guest_flag_state = TRUE;
        }
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_F_VERSION_1 %s available.\n", (guest_flag_state) ? "is" : "is NOT");
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_F_RING_PACKED %s available.\n", (packed_ring_guest_flag_state) ? "is" : "is NOT");
    #endif
    guest_flag_state = FALSE;
    if (CHECKBIT(adaptExt->features, VIRTIO_F_ANY_LAYOUT)) {
        guestFeatures |= (1ULL << VIRTIO_F_ANY_LAYOUT);
        guest_flag_state = TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_F_ANY_LAYOUT %s available.\n", (guest_flag_state) ? "is" : "is NOT");
    #endif
    guest_flag_state = FALSE;
    if (CHECKBIT(adaptExt->features, VIRTIO_F_ACCESS_PLATFORM)) {
        guestFeatures |= (1ULL << VIRTIO_F_ACCESS_PLATFORM);
        guest_flag_state = TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_F_ACCESS_PLATFORM %s available.\n", (guest_flag_state) ? "is" : "is NOT");
    #endif
    guest_flag_state = FALSE;
    if (CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX)) {
        guestFeatures |= (1ULL << VIRTIO_RING_F_EVENT_IDX);
        guest_flag_state = TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_RING_F_EVENT_IDX %s available.\n", (guest_flag_state) ? "is" : "is NOT");
    #endif
    guest_flag_state = FALSE;
    if (CHECKBIT(adaptExt->features, VIRTIO_RING_F_INDIRECT_DESC)) {
        guestFeatures |= (1ULL << VIRTIO_RING_F_INDIRECT_DESC);
        guest_flag_state = TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_RING_F_INDIRECT_DESC %s available.\n", (guest_flag_state) ? "is" : "is NOT");
    #endif
    guest_flag_state = FALSE;
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_CHANGE)) {
        guestFeatures |= (1ULL << VIRTIO_SCSI_F_CHANGE);
        guest_flag_state = TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_SCSI_F_CHANGE %s available.\n", (guest_flag_state) ? "is" : "is NOT");
    #endif
    guest_flag_state = FALSE;
    if (CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_HOTPLUG)) {
        guestFeatures |= (1ULL << VIRTIO_SCSI_F_HOTPLUG);
        guest_flag_state = TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    RhelDbgPrint(TRACE_GUEST_FEATURES, " Guest Feature VIRTIO_SCSI_F_HOTPLUG %s available.\n", (guest_flag_state) ? "is" : "is NOT");
    #endif
    
    if (!NT_SUCCESS(virtio_set_features(&adaptExt->vdev, guestFeatures))) {
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " virtio_set_features failed.\n");
        #endif
    } else {
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_GUEST_FEATURES, " virtio_set_features executed successfully.\n");
        #endif
    }

    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

BOOLEAN
InitVirtIODevice(
    IN PVOID DeviceExtension
    )
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    NTSTATUS status;

    status = virtio_device_initialize(
        &adaptExt->vdev,
        &VioScsiSystemOps,
        adaptExt,
        adaptExt->msix_enabled);
    if (!NT_SUCCESS(status)) {
        LogError(adaptExt,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " Failed to initialize virtio device, error %x\n", status);
        #endif
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
InitHW(
    IN PVOID DeviceExtension,
    IN PPORT_CONFIGURATION_INFORMATION ConfigInfo
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PACCESS_RANGE      accessRange;
    PADAPTER_EXTENSION adaptExt;
    ULONG pci_cfg_len, i;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    adaptExt->system_io_bus_number = ConfigInfo->SystemIoBusNumber;
    adaptExt->slot_number = ConfigInfo->SlotNumber;

    /* read PCI config space */
    pci_cfg_len = StorPortGetBusData(
        DeviceExtension,
        PCIConfiguration,
        ConfigInfo->SystemIoBusNumber,
        (ULONG)ConfigInfo->SlotNumber,
        (PVOID)&adaptExt->pci_config_buf,
        sizeof(adaptExt->pci_config_buf));

    if (pci_cfg_len != sizeof(adaptExt->pci_config_buf)) {
        LogError(DeviceExtension,
                SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_FATAL, " CANNOT READ PCI CONFIGURATION SPACE %d\n", pci_cfg_len);
        EXIT_FN();
        #endif
        return FALSE;
    }
    
    UCHAR CapOffset;
    PPCI_MSIX_CAPABILITY pMsixCapOffset;
    PPCI_COMMON_HEADER   pPciComHeader;
    pPciComHeader = &adaptExt->pci_config;
    if ((pPciComHeader->Status & PCI_STATUS_CAPABILITIES_LIST) == 0)
    {
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " NO CAPABILITIES_LIST\n");
        #endif
    } else
    {
        if ((pPciComHeader->HeaderType & (~PCI_MULTIFUNCTION)) == PCI_DEVICE_TYPE)
        {
            CapOffset = pPciComHeader->u.type0.CapabilitiesPtr;
            while (CapOffset != 0)
            {
                pMsixCapOffset = (PPCI_MSIX_CAPABILITY)&adaptExt->pci_config_buf[CapOffset];
                if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_MSIX)
                {
                    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                    RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_MSIX, Next Capability Offset = 0x%x", CapOffset);
                    RhelDbgPrint(TRACE_MSIX, "  MessageControl.TableSize = %lu \n", pMsixCapOffset->MessageControl.TableSize);
                    RhelDbgPrint(TRACE_MSIX, "  Number of MSI-X Table Entries (Vectors) : %lu \n", pMsixCapOffset->MessageControl.TableSize + 1);
                    RhelDbgPrint(TRACE_MSIX, "  MessageControl.FunctionMask = 0x%x \n", pMsixCapOffset->MessageControl.FunctionMask);
                    RhelDbgPrint(TRACE_MSIX, "  MessageControl.MSIXEnable = %lu \n", pMsixCapOffset->MessageControl.MSIXEnable);
                    RhelDbgPrint(TRACE_MSIX, "  MSI-X Table Offset : %lu \n", pMsixCapOffset->MessageTable.TableOffset);
                    RhelDbgPrint(TRACE_MSIX, "  MSI-X Pending Bit Array (PBA) Offset : 0x%x \n", pMsixCapOffset->PBATable.TableOffset);
                    #endif
                    adaptExt->msix_enabled = (pMsixCapOffset->MessageControl.MSIXEnable == 1);
                } else if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_VENDOR_SPECIFIC) { 
                    #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                    RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_VENDOR_SPECIFIC, Next Capability Offset = 0x%x \n", CapOffset);
                    #endif
                } else
                {
                    #if !defined(RUN_UNCHECKED)
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_POWER_MANAGEMENT) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_POWER_MANAGEMENT, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_AGP) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_AGP, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_VPD) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_VPD, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_SLOT_ID) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_SLOT_ID, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_MSI) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_MSI, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_CPCI_HOTSWAP) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_CPCI_HOTSWAP, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_PCIX) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_PCIX, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_HYPERTRANSPORT) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_HYPERTRANSPORT, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_VENDOR_SPECIFIC) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_VENDOR_SPECIFIC, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_DEBUG_PORT) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_DEBUG_PORT, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_CPCI_RES_CTRL) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_CPCI_RES_CTRL, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_SHPC) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_SHPC, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_P2P_SSID) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_P2P_SSID, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_AGP_TARGET) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_AGP_TARGET, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_SECURE) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_SECURE capability, Next Capability Offset = 0x%x \n", CapOffset); }
                    if (pMsixCapOffset->Header.CapabilityID == PCI_CAPABILITY_ID_PCI_EXPRESS) { 
                        RhelDbgPrint(TRACE_PCI_CAP, " CapabilityID = PCI_CAPABILITY_ID_PCI_EXPRESS, Next Capability Offset = 0x%x \n", CapOffset); }
                    #endif
                }
                CapOffset = pMsixCapOffset->Header.Next;
            }
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_MSIX, " MSI-X is : %s [msix_enabled]\n", (adaptExt->msix_enabled) ? "ENABLED" : "DISABLED");
            #endif
        } else
        {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_FATAL, " NOT A PCI_DEVICE_TYPE\n");
            #endif
            // FIXME
            // Should we not return on this error..?
            //EXIT_FN();
            //return FALSE;
        }
    }

    /* initialize the pci_bars array */
    for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++) {
        accessRange = *ConfigInfo->AccessRanges + i;
        if (accessRange->RangeLength != 0) {
            int iBar = virtio_get_bar_index(&adaptExt->pci_config, accessRange->RangeStart);
            if (iBar == -1) {
                #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
                RhelDbgPrint(TRACE_LEVEL_FATAL, " Cannot get index for BAR %I64d\n", accessRange->RangeStart.QuadPart);
                EXIT_FN();
                #endif
                return FALSE;
            }
            adaptExt->pci_bars[iBar].BasePA = accessRange->RangeStart;
            adaptExt->pci_bars[iBar].uLength = accessRange->RangeLength;
            adaptExt->pci_bars[iBar].bPortSpace = !accessRange->RangeInMemory;
        }
    }
    
    /* initialize the virtual device */
    if (!InitVirtIODevice(DeviceExtension)) {
        #if !defined(RUN_UNCHECKED)
        EXIT_FN();
        #endif
        return FALSE;
    }
    
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return TRUE;
}

BOOLEAN
SynchronizedKickEventRoutine(
    IN PVOID DeviceExtension,
    IN PVOID Context
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVirtIOSCSIEventNode eventNode   = (PVirtIOSCSIEventNode) Context;
    PVOID               va = NULL;
    ULONGLONG           pa = 0;

    if (virtqueue_add_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE],
                     &eventNode->sg,
                     0, 1,
                     eventNode, va, pa) >= 0){
        virtqueue_kick(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE]);
        #if !defined(RUN_UNCHECKED)
        EXIT_FN();
        #endif
        return TRUE;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_ERR();
    #endif
    return FALSE;
}


BOOLEAN
KickEvent(
    IN PVOID DeviceExtension,
    IN PVirtIOSCSIEventNode EventNode
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION adaptExt;
    ULONG              fragLen;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    RtlZeroMemory((PVOID)EventNode, sizeof(VirtIOSCSIEventNode));
    EventNode->sg.physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &EventNode->event, &fragLen);
    EventNode->sg.length   = sizeof(VirtIOSCSIEvent);
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return SynchronizedKickEventRoutine(DeviceExtension, (PVOID)EventNode);
}

VOID
VioScsiSpinLockManager(
    IN PVOID DeviceExtension,
    IN ULONG MessageId,
    IN OUT PSTOR_LOCK_HANDLE LockHandle,
    IN STOR_SPINLOCK LockMode,
    IN BOOLEAN LockOp
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVOID               LockContext = NULL; //sanity check for LockMode = InterruptLock or StartIoLock
    #if !defined(RUN_UNCHECKED)
    PVOID               TraceLockMode = "DpcLock";
    #endif
    
    if (LockOp == VIOSCSI_VQLOCKOP_LOCK) {
        if (LockMode == DpcLock) {
            ULONG QueueNumber = MESSAGE_TO_QUEUE(MessageId);
            ULONG vq_req_idx = QueueNumber - VIRTIO_SCSI_REQUEST_QUEUE_0;
            LockContext = &adaptExt->dpc[vq_req_idx];
        } else {
            #if !defined(RUN_UNCHECKED)
            TraceLockMode = "InterruptLock";
            #endif
        }
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LOCKS, " Obtaining %s Spin Lock...\n", TraceLockMode);
        #endif
        StorPortAcquireSpinLock(DeviceExtension, LockMode, LockContext, LockHandle);
    } else {
        #if !defined(RUN_UNCHECKED)
        if (LockMode == InterruptLock) {
            TraceLockMode = "InterruptLock";
        }
        RhelDbgPrint(TRACE_LOCKS, " Releasing %s Spin Lock...\n", TraceLockMode);
        #endif
        StorPortReleaseSpinLock(DeviceExtension, LockHandle);
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
}

ULONG
VioScsiSpinLockManagerEx(
    IN PVOID DeviceExtension,
    IN ULONG MessageId,
    IN OUT PSTOR_LOCK_HANDLE LockHandle,
    IN STOR_SPINLOCK LockMode,
    IN BOOLEAN LockOp
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN();
    #endif

    PADAPTER_EXTENSION  adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ULONG               lock_result = STOR_STATUS_NOT_IMPLEMENTED;
    PVOID               LockContext = NULL; //sanity check for LockMode = InterruptLock or StartIoLock
    PVOID               TraceLockMode = "DpcLock";

    switch (LockMode) {
    case DpcLock:
        TraceLockMode = "DpcLock";
        break;
    case StartIoLock:
        TraceLockMode = "StartIoLock";
        break;
    case InterruptLock:
        TraceLockMode = "InterruptLock";
        break;
    case MSIXLock:
        if (adaptExt->msix_enabled) {
            switch (LockOp) {
            case VIOSCSI_VQLOCKOP_LOCK:
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LOCKS, " Obtaining MSI-X Spin Lock...\n");
                #endif
                ULONG oldIrql = 0;
                lock_result = StorPortAcquireMSISpinLock(DeviceExtension, MessageId, &oldIrql);
                LockHandle->Context.OldIrql = (KIRQL)oldIrql;
                break;
            case VIOSCSI_VQLOCKOP_UNLOCK:
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LOCKS, " Releasing a MSI-X Spin Lock...\n");
                #endif
                lock_result = StorPortReleaseMSISpinLock(DeviceExtension, MessageId, LockHandle->Context.OldIrql);
                break;
            default:
                #if !defined(RUN_UNCHECKED)
                RhelDbgPrint(TRACE_LEVEL_ERROR, " ERROR: Unknown Lock Operation Type..!!! %d\n", LockOp);
                #endif
                break;
            }
            if (lock_result == STOR_STATUS_SUCCESS) {
                #if !defined(RUN_UNCHECKED)
                EXIT_FN();
                #endif
                return lock_result ;
            }
        } else {
            #if !defined(RUN_UNCHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " WARNING: Unable to obtain MSI-X Spinlock or MSI-X is unavailable for this adapter. Using fallback method instead (DpcLock).\n");
            #endif
            TraceLockMode = "DpcLock";
            LockMode = DpcLock;
        }
        break;
    default:
        TraceLockMode = "DpcLock";
        break;
    }
    switch (LockOp) {
    case VIOSCSI_VQLOCKOP_LOCK:
        if (LockMode == DpcLock) {
            ULONG QueueNumber = MESSAGE_TO_QUEUE(MessageId);
            ULONG vq_req_idx = QueueNumber - VIRTIO_SCSI_REQUEST_QUEUE_0;
            LockContext = &adaptExt->dpc[vq_req_idx];
        }
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LOCKS, " Obtaining %s Spin Lock...\n", TraceLockMode);
        #endif
        StorPortAcquireSpinLock(DeviceExtension, LockMode, LockContext, LockHandle);
        break;
    case VIOSCSI_VQLOCKOP_UNLOCK:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LOCKS, " Releasing %s Spin Lock...\n", TraceLockMode);
        #endif
        StorPortReleaseSpinLock(DeviceExtension, LockHandle);
        break;
    default:
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_ERROR, " ERROR: Unknown Lock Operation Type %d\n", LockOp);
        #endif
        break;
    }
    /*
     * Do not set lock_result = STOR_STATUS_SUCCESS; here so we can 
     * pass through the MSI-X based Spinlock result instead.
     * Calls to StorPortAcquireSpinLock() and StorPortReleaseSpinLock() do not return a status.
     * 
     */
    #if !defined(RUN_UNCHECKED)
    EXIT_FN();
    #endif
    return lock_result ;
}

VOID FirmwareRequest(
    IN PVOID DeviceExtension,
    IN PSRB_TYPE Srb
    )
{
    #if !defined(RUN_UNCHECKED)
    ENTER_FN_SRB();
    #endif

    PADAPTER_EXTENSION  adaptExt;
    PSRB_EXTENSION      srbExt   = NULL;
    ULONG                   dataLen = 0;
    PSRB_IO_CONTROL         srbControl = NULL;
    PFIRMWARE_REQUEST_BLOCK firmwareRequest = NULL;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    srbExt = SRB_EXTENSION(Srb);
    srbControl = (PSRB_IO_CONTROL)SRB_DATA_BUFFER(Srb);
    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);
    if (dataLen < (sizeof(SRB_IO_CONTROL) + sizeof(FIRMWARE_REQUEST_BLOCK))) {
        srbControl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BAD_SRB_BLOCK_LENGTH);
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_ERROR, " FirmwareRequest Bad Block Length  %ul\n", dataLen);
        EXIT_FN_SRB();
        #endif
        return;
    }

    firmwareRequest = (PFIRMWARE_REQUEST_BLOCK)(srbControl + 1);
    switch (firmwareRequest->Function) {

    case FIRMWARE_FUNCTION_GET_INFO: {
        PSTORAGE_FIRMWARE_INFO_V2   firmwareInfo;
        firmwareInfo = (PSTORAGE_FIRMWARE_INFO_V2)((PUCHAR)srbControl + firmwareRequest->DataBufferOffset);
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " FIRMWARE_FUNCTION_GET_INFO \n");
        #endif
        if ((firmwareInfo->Version >= STORAGE_FIRMWARE_INFO_STRUCTURE_VERSION_V2) ||
            (firmwareInfo->Size >= sizeof(STORAGE_FIRMWARE_INFO_V2))) {
            firmwareInfo->Version = STORAGE_FIRMWARE_INFO_STRUCTURE_VERSION_V2;
            firmwareInfo->Size = sizeof(STORAGE_FIRMWARE_INFO_V2);

            firmwareInfo->UpgradeSupport = TRUE;

            firmwareInfo->SlotCount = 1;
            firmwareInfo->ActiveSlot = 0;
            firmwareInfo->PendingActivateSlot = STORAGE_FIRMWARE_INFO_INVALID_SLOT;
            firmwareInfo->FirmwareShared = FALSE;
            firmwareInfo->ImagePayloadAlignment = PAGE_SIZE;
            firmwareInfo->ImagePayloadMaxSize = PAGE_SIZE;

            if (firmwareRequest->DataBufferLength >= (sizeof(STORAGE_FIRMWARE_INFO_V2) + sizeof(STORAGE_FIRMWARE_SLOT_INFO_V2))) {
                firmwareInfo->Slot[0].SlotNumber = 0;
                firmwareInfo->Slot[0].ReadOnly = FALSE;
                StorPortCopyMemory(&firmwareInfo->Slot[0].Revision, &adaptExt->fw_ver, sizeof (adaptExt->fw_ver));
                srbControl->ReturnCode = FIRMWARE_STATUS_SUCCESS;
            } else {
                firmwareRequest->DataBufferLength = sizeof(STORAGE_FIRMWARE_INFO_V2) + sizeof(STORAGE_FIRMWARE_SLOT_INFO_V2);
                srbControl->ReturnCode = FIRMWARE_STATUS_OUTPUT_BUFFER_TOO_SMALL;
            }
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
        }
        else {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " Wrong Version %ul or Size %ul\n", firmwareInfo->Version, firmwareInfo->Size);
            #endif
            srbControl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BAD_SRB_BLOCK_LENGTH);
        }
    }
    break;
    case FIRMWARE_FUNCTION_DOWNLOAD: {
        PSTORAGE_FIRMWARE_DOWNLOAD_V2   firmwareDwnld;
        firmwareDwnld = (PSTORAGE_FIRMWARE_DOWNLOAD_V2)((PUCHAR)srbControl + firmwareRequest->DataBufferOffset);
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " FIRMWARE_FUNCTION_DOWNLOAD \n");
        #endif
        if ((firmwareDwnld->Version >= STORAGE_FIRMWARE_DOWNLOAD_STRUCTURE_VERSION_V2) ||
            (firmwareDwnld->Size >= sizeof(STORAGE_FIRMWARE_DOWNLOAD_V2))) {
            firmwareDwnld->Version = STORAGE_FIRMWARE_DOWNLOAD_STRUCTURE_VERSION_V2;
            firmwareDwnld->Size = sizeof(STORAGE_FIRMWARE_DOWNLOAD_V2);
            adaptExt->fw_ver++;
            srbControl->ReturnCode = FIRMWARE_STATUS_SUCCESS;
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
        }
        else {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " Wrong Version %ul or Size %ul\n", firmwareDwnld->Version, firmwareDwnld->Size);
            #endif
            srbControl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BAD_SRB_BLOCK_LENGTH);
        }
    }
    break;
    case FIRMWARE_FUNCTION_ACTIVATE: {
        PSTORAGE_FIRMWARE_ACTIVATE firmwareActivate;
        firmwareActivate = (PSTORAGE_FIRMWARE_ACTIVATE)((PUCHAR)srbControl + firmwareRequest->DataBufferOffset);
        if ((firmwareActivate->Version == STORAGE_FIRMWARE_ACTIVATE_STRUCTURE_VERSION) ||
            (firmwareActivate->Size >= sizeof(STORAGE_FIRMWARE_ACTIVATE))) {
            firmwareActivate->Version = STORAGE_FIRMWARE_ACTIVATE_STRUCTURE_VERSION;
            firmwareActivate->Size = sizeof(STORAGE_FIRMWARE_ACTIVATE);
            srbControl->ReturnCode = FIRMWARE_STATUS_SUCCESS;
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
        }
        else {
            #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
            RhelDbgPrint(TRACE_LEVEL_ERROR, " Wrong Version %ul or Size %ul\n", firmwareActivate->Version, firmwareActivate->Size);
            #endif
            srbControl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BAD_SRB_BLOCK_LENGTH);
        }
        #if !defined(RUN_UNCHECKED)
        RhelDbgPrint(TRACE_LEVEL_VERBOSE, " FIRMWARE_FUNCTION_ACTIVATE \n");
        #endif
    }
    break;
    default:
        #if !defined(RUN_UNCHECKED) || defined(RUN_MIN_CHECKED)
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Unsupported Function %ul\n", firmwareRequest->Function);
        #endif
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_INVALID_REQUEST);
        break;
    }
    #if !defined(RUN_UNCHECKED)
    EXIT_FN_SRB();
    #endif
}
