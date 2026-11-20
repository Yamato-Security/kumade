// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
// SDK-only VSS ABI bridge; snapshot policy, paths and evidence stay in Rust.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <strsafe.h>

static const GUID software_provider =
    {0xb5946137, 0x7b9f, 0x4925, {0xaf,0x80,0x51,0xab,0xd6,0x0b,0x20,0xd5}};
using CreateFn = HRESULT (STDAPICALLTYPE *)(IVssBackupComponents **);
using FreePropsFn = void (APIENTRY *)(VSS_SNAPSHOT_PROP *);

struct Client {
    IVssBackupComponents *backup;
    HMODULE module;
    FreePropsFn free_props;
    GUID set;
    bool com;
};
struct Snapshot {
    GUID id;
    GUID set;
    GUID provider;
    LONGLONG created;
    LONG attributes;
    LONG count;
    WCHAR original[128];
    WCHAR device[512];
};

extern "C" HRESULT kumade_vss_close(Client *c) {
    if (!c) return S_OK;
    HRESULT result = S_OK;
    if (c->backup) {
        if (!IsEqualGUID(c->set, GUID_NULL)) {
            LONG deleted = 0;
            GUID not_deleted = GUID_NULL;
            // Only this requester's set ID. Never enumerate/delete other snapshots.
            result = c->backup->DeleteSnapshots(c->set, VSS_OBJECT_SNAPSHOT_SET,
                                               FALSE, &deleted, &not_deleted);
            if (result == VSS_E_OBJECT_NOT_FOUND) result = S_OK;
        }
        // Auto-release context also releases snapshots on requester disconnect.
        c->backup->Release();
    }
    if (c->com) CoUninitialize();
    if (c->module) FreeLibrary(c->module);
    HeapFree(GetProcessHeap(), 0, c);
    return result;
}

extern "C" HRESULT kumade_vss_open(Client **output) {
    if (!output) return E_POINTER;
    *output = nullptr;
    Client *c = static_cast<Client *>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Client)));
    if (!c) return E_OUTOFMEMORY;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) { HeapFree(GetProcessHeap(), 0, c); return hr; }
    c->com = true;
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE, nullptr);
    if (hr == RPC_E_TOO_LATE) hr = S_OK;
    // Delay-load VSS so normal acquisition still starts on unsupported systems.
    if (SUCCEEDED(hr)) {
        c->module = LoadLibraryExW(L"vssapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!c->module) hr = HRESULT_FROM_WIN32(GetLastError());
    }
    if (SUCCEEDED(hr)) {
        FARPROC create_address = GetProcAddress(c->module, "CreateVssBackupComponentsInternal");
        FARPROC free_address = GetProcAddress(c->module, "VssFreeSnapshotPropertiesInternal");
        // Some native x86 SDK implementations export stdcall-decorated names.
        if (!create_address) create_address = GetProcAddress(c->module, "_CreateVssBackupComponentsInternal@4");
        if (!free_address) free_address = GetProcAddress(c->module, "_VssFreeSnapshotPropertiesInternal@4");
        CreateFn create = nullptr;
        static_assert(sizeof(create) == sizeof(create_address), "Windows function pointer ABI");
        static_assert(sizeof(c->free_props) == sizeof(free_address), "Windows function pointer ABI");
        CopyMemory(&create, &create_address, sizeof(create));
        CopyMemory(&c->free_props, &free_address, sizeof(c->free_props));
        if (!create || !c->free_props) hr = HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        else hr = create(&c->backup);
    }
    if (SUCCEEDED(hr) && !c->backup) hr = E_UNEXPECTED;
    if (SUCCEEDED(hr)) hr = c->backup->InitializeForBackup();
    if (SUCCEEDED(hr)) hr = c->backup->SetBackupState(FALSE, FALSE, VSS_BT_COPY, FALSE);
    // Crash-consistent, no application writers, no persistence/no-auto-release.
    if (SUCCEEDED(hr)) hr = c->backup->SetContext(VSS_CTX_FILE_SHARE_BACKUP);
    if (FAILED(hr)) { kumade_vss_close(c); return hr; }
    *output = c;
    return S_OK;
}

extern "C" HRESULT kumade_vss_supported(Client *c, const WCHAR *volume, BOOL *supported) {
    if (!c || !volume || !supported) return E_POINTER;
    return c->backup->IsVolumeSupported(software_provider, const_cast<WCHAR *>(volume), supported);
}
extern "C" HRESULT kumade_vss_start(Client *c) {
    if (!c) return E_POINTER;
    return c->backup->StartSnapshotSet(&c->set);
}
extern "C" HRESULT kumade_vss_add(Client *c, const WCHAR *volume, GUID *id) {
    if (!c || !volume || !id) return E_POINTER;
    return c->backup->AddToSnapshotSet(const_cast<WCHAR *>(volume), software_provider, id);
}
extern "C" HRESULT kumade_vss_commit(Client *c, DWORD timeout_ms) {
    if (!c) return E_POINTER;
    IVssAsync *operation = nullptr;
    HRESULT hr = c->backup->DoSnapshotSet(&operation);
    if (FAILED(hr)) return hr;
    if (!operation) return E_UNEXPECTED;
    HRESULT waited = operation->Wait(timeout_ms);
    HRESULT status = VSS_S_ASYNC_PENDING;
    hr = operation->QueryStatus(&status, nullptr);
    if (FAILED(waited) || FAILED(hr) || status == VSS_S_ASYNC_PENDING) {
        operation->Cancel();
        operation->Wait(30000);
        operation->Release();
        if (FAILED(hr)) return hr;
        if (FAILED(waited)) return waited;
        return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    }
    operation->Release();
    return status == VSS_S_ASYNC_FINISHED ? S_OK : (FAILED(status) ? status : E_ABORT);
}
extern "C" HRESULT kumade_vss_properties(Client *c, const GUID *id, Snapshot *output) {
    if (!c || !id || !output) return E_POINTER;
    ZeroMemory(output, sizeof(*output));
    VSS_SNAPSHOT_PROP p = {};
    HRESULT hr = c->backup->GetSnapshotProperties(*id, &p);
    if (FAILED(hr)) return hr;
    if (!p.m_pwszOriginalVolumeName || !p.m_pwszSnapshotDeviceObject ||
        p.m_eStatus != VSS_SS_CREATED || !IsEqualGUID(p.m_SnapshotSetId, c->set) ||
        (p.m_lSnapshotAttributes & VSS_VOLSNAP_ATTR_NO_AUTO_RELEASE)) {
        hr = E_UNEXPECTED;
    } else {
        output->id = p.m_SnapshotId;
        output->set = p.m_SnapshotSetId;
        output->provider = p.m_ProviderId;
        output->created = p.m_tsCreationTimestamp;
        output->attributes = p.m_lSnapshotAttributes;
        output->count = p.m_lSnapshotsCount;
        hr = StringCchCopyW(output->original, 128, p.m_pwszOriginalVolumeName);
        if (SUCCEEDED(hr)) hr = StringCchCopyW(output->device, 512, p.m_pwszSnapshotDeviceObject);
    }
    c->free_props(&p);
    return hr;
}
extern "C" size_t kumade_vss_snapshot_size() { return sizeof(Snapshot); }
