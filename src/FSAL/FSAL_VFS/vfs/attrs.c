/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) CohortFS LLC, 2015
 * Author: Daniel Gryniewicz dang@cohortfs.com
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * -------------
 */

/* attrs.c
 * VFS attribute caching handle object
 */

#include "config.h"

#include <attr/xattr.h>
#include "fsal.h"
#include "fsal_convert.h"
#include "FSAL/access_check.h"
#include "../vfs_methods.h"
#include "attrs.h"
#include "nfs4_acls.h"
#include "nfs41acl.h"

#define ACES_2_ACLSIZE(naces)	(sizeof(nfsacl41i) + (naces * sizeof(nfsace4i)))
#define	ACES_2_XDRSIZE(naces) 	((sizeof(u_int) * 2) + (naces * sizeof(nfsace4i)))
#define NFS4_XATTR "system.nfs4_acl_xdr"

/*
 * Native NFSv4 ACLs
 */
static int
acep_to_nfsace4i(const fsal_ace_t *acep, nfsace4i *nacep)
{
	nacep->type = acep->type;
	nacep->flag = acep->flag;
	nacep->access_mask = acep->perm;
	nacep->iflag = acep->iflag & FSAL_ACE_IFLAG_SPECIAL_ID ? ACEI4_SPECIAL_WHO : 0;
	nacep->who = GET_FSAL_ACE_WHO(*acep);
}

static int
fsal_acl_to_nfsacl41i(const fsal_acl_t *fsalaclp, nfsacl41i **_nacl)
{
	nfsacl41i *nacl = NULL;
	nfsace4i *nacep = NULL;
	fsal_ace_t *f_ace = NULL;

	int i, error;
	size_t acl_size;

	acl_size = ACES_2_ACLSIZE(fsalaclp->naces);
	nacl = calloc(1, acl_size);
	if (nacl == NULL) {
		errno = ENOMEM;
		return -1;
	}

	nacl->na41_aces.na41_aces_len = fsalaclp->naces;
	/* TODO: set na41_flag */
	nacep = (nfsace4i *)((char *)nacl + sizeof (nfsacl41i));
	nacl->na41_aces.na41_aces_val = nacep;

	for (f_ace = fsalaclp->aces;
	    f_ace < fsalaclp->aces + fsalaclp->naces; f_ace++) {
		nacep = &nacl->na41_aces.na41_aces_val[i];
		acep_to_nfsace4i(f_ace, nacep);
	}
	*_nacl = nacl;
	return 0;
}

static int
set_native_nfs4_acl(int fd, const fsal_acl_t *aclp)
{
	nfsacl41i *nacl = NULL;
	char *bufp = NULL;
	XDR xdr = {0};
	size_t xdr_size = ACES_2_XDRSIZE(aclp->naces);
	int error;
	bool ok;

	error = fsal_acl_to_nfsacl41i(aclp, &nacl);
	if (error) {
		return -1;
	}	

	bufp = (char*) calloc(1, ACES_2_ACLSIZE(aclp->naces));
	if (bufp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	xdrmem_create(&xdr, bufp, xdr_size, XDR_ENCODE);
	ok = xdr_nfsacl41i(&xdr, nacl);
	if (!ok) {
		free(nacl);
		free(bufp);
		errno = ENOMEM;
		return -1;
	}
	free(nacl);

	error = fsetxattr(fd, NFS4_XATTR, bufp, ACES_2_ACLSIZE(aclp->naces), 0);	
	free(bufp);
	return error;
}

static void
nfsace4i_to_acep(const nfsace4i *nacep, fsal_ace_t *acep)
{
	acep->type = nacep->type;
	acep->flag = nacep->flag;
	acep->perm = nacep->access_mask;
	acep->iflag = nacep->iflag & ACEI4_SPECIAL_WHO ? FSAL_ACE_IFLAG_SPECIAL_ID : 0;
	if (IS_FSAL_ACE_GROUP_ID(*acep)) {
		acep->who.gid = nacep->who;
	} else {
		acep->who.uid = nacep->who;
	}
}

static void
nfsacl41i_to_fsal_acl(const nfsacl41i *nacl, fsal_ace_t **ace)
{
	int i;
	fsal_ace_t *pace = NULL;

	pace = *ace;

	for (i = 0; i < nacl->na41_aces.na41_aces_len; i++) {
		nfsace4i *nacep = &nacl->na41_aces.na41_aces_val[i];
		nfsace4i_to_acep(nacep, pace);
		pace += 1;
	}

	pace -= 1;
	return;
}

static int
get_native_nfs4_acl(int fd, struct nfsacl41i **naclp)
{
	size_t rv;
	bool ok;
	char *value = NULL, *bufp = NULL;
	struct nfsacl41i *nacl = NULL;
	uint num_aces;
	XDR xdr = {0};

	rv = fgetxattr(fd, NFS4_XATTR, value, 0);
	if (rv == -1) {
		return -1;
	}

	value = calloc(rv, 1);
	if (value == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (fgetxattr(fd, NFS4_XATTR, value, rv) == -1) {
		free(value);
		return -1;
	}

	nacl = calloc(1, sizeof(nfsacl41i));

	xdrmem_create(&xdr, value, rv, XDR_DECODE);
	ok = xdr_nfsacl41i(&xdr, nacl);
	if (!ok) {
		errno = ENOMEM;
		free(value);
		free(nacl);
		return -1;
	}

	free(value);
	*naclp = nacl;

	return 0;
}

static fsal_acl_status_t
get_fsal_acl_nfsv4(struct vfs_fsal_obj_handle *vfs_hdl,
		   int id, fsal_acl_t **pacl)
{
	fsal_acl_status_t status = NFS_V4_ACL_SUCCESS;
	fsal_acl_data_t acldata;
	struct nfsacl41i *nacl = NULL;
	fsal_acl_t *acl;
	int error;

	error = get_native_nfs4_acl(id, &nacl);
	if (error) {
		LogCrit(COMPONENT_FSAL,
			"Failed to get NFS4 ACL: %s",
			strerror(errno));

		return NFS_V4_ACL_INTERNAL_ERROR;
	}

	acldata.naces = nacl->na41_aces.na41_aces_len;
	acldata.aces = (fsal_ace_t *) nfs4_ace_alloc(acldata.naces);
	nfsacl41i_to_fsal_acl(nacl, &acldata.aces);
	acl = nfs4_acl_new_entry(&acldata, &status);

	free(nacl-> na41_aces.na41_aces_val);
	free(nacl);

	*pacl = acl;
	return status;
}

static fsal_acl_status_t
set_fsal_acl_nfsv4(struct vfs_fsal_obj_handle *vfs_hdl,
		   int fd, attrmask_t request_mask,
		   struct fsal_attrlist *attrib)
{
	int error;

	error = set_native_nfs4_acl(fd, attrib->acl);
	if (error) {
		LogCrit(COMPONENT_FSAL,
			"Failed to get NFS4 ACL: %s",
			strerror(errno));

		return NFS_V4_ACL_INTERNAL_ERROR;
	}

	return NFS_V4_ACL_SUCCESS;
}

/*
 * POSIX1E ACLs
 */


fsal_status_t vfs_sub_getattrs(struct vfs_fsal_obj_handle *vfs_hdl,
			       int fd, attrmask_t request_mask,
			       struct fsal_attrlist *attrib)
{
	fsal_acl_status_t status = NFS_V4_ACL_SUCCESS;
	fsal_acl_t *acl = NULL;
	fsal_status_t fsal_st = {ERR_FSAL_NO_ERROR, 0};

	if (FSAL_TEST_MASK(request_mask, ATTR4_FS_LOCATIONS) &&
	    vfs_hdl->obj_handle.obj_ops->is_referral(&vfs_hdl->obj_handle,
		attrib, false /*cache_attrs*/)) {

		fsal_st = vfs_get_fs_locations(vfs_hdl, fd, attrib);
		if (FSAL_IS_ERROR(fsal_st)) {
			/* No error should be returned here, any major error
			 * should have been caught before this */
			LogDebug(COMPONENT_FSAL,
				 "Could not get the fs locations for vfs "
				 "handle: %p", vfs_hdl);
		}
	}

	switch (vfs_hdl->acl_brand) {
	case ACL_BRAND_POSIX:
#if 0
		status = get_fsal_acl_posix1e(vfs_hdl, fd, request_mask, attrib, &acl);
		attrib->acl = acl;
		FSAL_SET_MASK(attrib->valid_mask, ATTR_ACL);
#endif
		break;
	case ACL_BRAND_NFS41:
		status = get_fsal_acl_nfsv4(vfs_hdl, fd, &acl);
		attrib->acl = acl;
		FSAL_SET_MASK(attrib->valid_mask, ATTR_ACL);
		break;
	default:
		break;
	}
	if (status != NFS_V4_ACL_SUCCESS) {
		return fsalstat(ERR_FSAL_FAULT, status);
	} 

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

fsal_status_t vfs_sub_setattrs(struct vfs_fsal_obj_handle *vfs_hdl,
			       int fd, attrmask_t request_mask,
			       struct fsal_attrlist *attrib)
{
	fsal_acl_status_t status = NFS_V4_ACL_SUCCESS;

	if (!ACL_ENABLED(vfs_hdl) ||
	    !FSAL_TEST_MASK(request_mask, ATTR_ACL) ||
	    !attrib || !attrib->acl) {
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}

	fsal_print_acl(COMPONENT_FSAL, NIV_FULL_DEBUG, attrib->acl);
	switch (vfs_hdl->acl_brand) {
	case ACL_BRAND_POSIX:
#if 0
		status = set_fsal_acl_posix1e(vfs_hdl, fd, request_mask, attrib);
#endif
		break;
	case ACL_BRAND_NFS41:
		status = set_fsal_acl_nfsv4(vfs_hdl, fd, request_mask, attrib);
		break;
	default:
		break;
	}

	if (status != NFS_V4_ACL_SUCCESS) {
		return fsalstat(ERR_FSAL_FAULT, status);
	} 

	FSAL_SET_MASK(attrib->valid_mask, ATTR_ACL);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}
