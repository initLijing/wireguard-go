/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package resource

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func MAKEINTRESOURCE(i uint16) *uint16 {
	return (*uint16)(unsafe.Pointer(uintptr(i)))
}

// Predefined Resource Types
var (
	RT_CURSOR                                          = MAKEINTRESOURCE(1)
	RT_BITMAP                                          = MAKEINTRESOURCE(2)
	RT_ICON                                            = MAKEINTRESOURCE(3)
	RT_MENU                                            = MAKEINTRESOURCE(4)
	RT_DIALOG                                          = MAKEINTRESOURCE(5)
	RT_STRING                                          = MAKEINTRESOURCE(6)
	RT_FONTDIR                                         = MAKEINTRESOURCE(7)
	RT_FONT                                            = MAKEINTRESOURCE(8)
	RT_ACCELERATOR                                     = MAKEINTRESOURCE(9)
	RT_RCDATA                                          = MAKEINTRESOURCE(10)
	RT_MESSAGETABLE                                    = MAKEINTRESOURCE(11)
	RT_GROUP_CURSOR                                    = MAKEINTRESOURCE(12)
	RT_GROUP_ICON                                      = MAKEINTRESOURCE(14)
	RT_VERSION                                         = MAKEINTRESOURCE(16)
	RT_DLGINCLUDE                                      = MAKEINTRESOURCE(17)
	RT_PLUGPLAY                                        = MAKEINTRESOURCE(19)
	RT_VXD                                             = MAKEINTRESOURCE(20)
	RT_ANICURSOR                                       = MAKEINTRESOURCE(21)
	RT_ANIICON                                         = MAKEINTRESOURCE(22)
	RT_HTML                                            = MAKEINTRESOURCE(23)
	RT_MANIFEST                                        = MAKEINTRESOURCE(24)
	CREATEPROCESS_MANIFEST_RESOURCE_ID                 = MAKEINTRESOURCE(1)
	ISOLATIONAWARE_MANIFEST_RESOURCE_ID                = MAKEINTRESOURCE(2)
	ISOLATIONAWARE_NOSTATICIMPORT_MANIFEST_RESOURCE_ID = MAKEINTRESOURCE(3)
	ISOLATIONPOLICY_MANIFEST_RESOURCE_ID               = MAKEINTRESOURCE(4)
	ISOLATIONPOLICY_BROWSER_MANIFEST_RESOURCE_ID       = MAKEINTRESOURCE(5)
	MINIMUM_RESERVED_MANIFEST_RESOURCE_ID              = MAKEINTRESOURCE(1 /*inclusive*/)
	MAXIMUM_RESERVED_MANIFEST_RESOURCE_ID              = MAKEINTRESOURCE(16 /*inclusive*/)
)

//sys	findResource(module windows.Handle, name *uint16, resType *uint16) (resInfo windows.Handle, err error) = kernel32.FindResourceW

func FindByID(module windows.Handle, id uint16, resType *uint16) (resInfo windows.Handle, err error) {
	return findResource(module, MAKEINTRESOURCE(id), resType)
}

func FindByName(module windows.Handle, name string, resType *uint16) (resInfo windows.Handle, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	resInfo, err = findResource(module, name16, resType)
	return
}

//sys	Sizeof(module windows.Handle, resInfo windows.Handle) (size uint32, err error) = kernel32.SizeofResource
//sys	Load(module windows.Handle, resInfo windows.Handle) (resData windows.Handle, err error) = kernel32.LoadResource
//sys	Lock(resData windows.Handle) (addr uintptr, err error) = kernel32.LockResource
