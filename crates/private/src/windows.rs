//! Windows: owner SIDs, DACLs and reparse points in place of modes, uids and
//! `O_NOFOLLOW`. Public so local IPC (named pipes) can reuse the same
//! definition of "this user".

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, GetTokenInformation, INHERIT_ONLY_ACE, InitializeAcl,
    InitializeSecurityDescriptor, IsWellKnownSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Closes a kernel handle on drop.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by us and is closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// One token information class, owned in an 8-aligned buffer.
fn token_information(token: HANDLE, class: i32) -> io::Result<Vec<u64>> {
    let mut needed = 0_u32;
    // SAFETY: a size query with a null buffer is the documented form.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buffer` is at least `needed` bytes and 8-aligned.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

/// The identity of a process: its user SID, and the default owner it stamps
/// on objects it creates. For an elevated administrator the default owner is
/// the Administrators group, not the user, so "owned by us" means either.
pub struct ProcessUser {
    user: Vec<u64>,
    owner: Vec<u64>,
}

impl ProcessUser {
    /// This process.
    pub fn current() -> io::Result<Self> {
        // SAFETY: GetCurrentProcess returns a pseudo-handle needing no close.
        Self::of_process(unsafe { GetCurrentProcess() })
    }

    fn of_process(process: HANDLE) -> io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `process` is a live handle; `token` is a valid out-pointer.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle(token);
        Ok(Self {
            user: token_information(token.0, TokenUser)?,
            owner: token_information(token.0, TokenOwner)?,
        })
    }

    /// The user SID; valid while `self` lives.
    pub fn sid(&self) -> PSID {
        // SAFETY: the buffer holds a kernel-written TOKEN_USER whose SID points
        // into the same buffer.
        unsafe { (*self.user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn default_owner(&self) -> PSID {
        // SAFETY: as for `sid`, with TOKEN_OWNER.
        unsafe { (*self.owner.as_ptr().cast::<TOKEN_OWNER>()).Owner }
    }

    /// Whether `sid` is this user, or the default owner this user's
    /// processes give their objects.
    fn owns(&self, sid: PSID) -> bool {
        // SAFETY: both SIDs are valid for the duration of the call.
        unsafe { EqualSid(sid, self.sid()) != 0 || EqualSid(sid, self.default_owner()) != 0 }
    }
}

/// Whether process `pid` runs as the same user as this one.
///
/// Used to authenticate both ends of a named pipe, the Windows counterpart of
/// checking a Unix socket peer's uid.
pub fn process_is_current_user(pid: u32) -> io::Result<bool> {
    // SAFETY: OpenProcess has no memory preconditions.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = Handle(process);
    let peer = ProcessUser::of_process(process.0)?;
    let current = ProcessUser::current()?;
    // SAFETY: both SIDs are valid while their owners live.
    Ok(unsafe { EqualSid(peer.sid(), current.sid()) } != 0)
}

/// An absolute security descriptor whose protected DACL grants this user full
/// access and names nobody else. Heap-pinned: the descriptor points at the
/// ACL and the attributes point at the descriptor.
pub struct OwnerOnly {
    _user: ProcessUser,
    _acl: Vec<u64>,
    _descriptor: Box<SECURITY_DESCRIPTOR>,
    attributes: Box<SECURITY_ATTRIBUTES>,
}

// SAFETY: every pointer inside refers to heap memory owned by the value
// itself and is never written after construction; the kernel only reads it.
unsafe impl Send for OwnerOnly {}
// SAFETY: as above; shared references expose no mutation.
unsafe impl Sync for OwnerOnly {}

impl OwnerOnly {
    /// `inheritable` also applies the grant to files and directories later
    /// created inside a directory that carries it.
    pub fn new(inheritable: bool) -> io::Result<Self> {
        let user = ProcessUser::current()?;
        // SAFETY: the SID came from the token and is valid.
        let sid_len = unsafe { GetLengthSid(user.sid()) } as usize;
        // ACL header + one ACCESS_ALLOWED_ACE whose SidStart is the SID.
        let acl_len =
            size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_len;
        let mut acl = vec![0_u64; acl_len.div_ceil(8)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        let flags = if inheritable {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let descriptor_ptr = (&raw mut *descriptor).cast::<c_void>();
        // SAFETY: every pointer refers to a live buffer of sufficient size;
        // the heap buffers do not move when `Self` does.
        unsafe {
            if InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) == 0
                || AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, flags, FILE_ALL_ACCESS, user.sid())
                    == 0
                || InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) == 0
                || SetSecurityDescriptorDacl(descriptor_ptr, 1, acl_ptr, 0) == 0
                // Protected: ACEs from the parent are not inherited.
                || SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                    == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let attributes = Box::new(SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor_ptr,
            bInheritHandle: 0,
        });
        Ok(Self {
            _user: user,
            _acl: acl,
            _descriptor: descriptor,
            attributes,
        })
    }

    /// For `CreateFileW`, `CreateNamedPipeW` and friends; valid while `self`
    /// lives.
    pub fn security_attributes(&self) -> *mut SECURITY_ATTRIBUTES {
        (&raw const *self.attributes).cast_mut()
    }

    fn acl(&self) -> *const ACL {
        self._acl.as_ptr().cast()
    }
}

pub(super) fn open_nofollow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    // With FILE_FLAG_OPEN_REPARSE_POINT a link is opened as itself; refuse it
    // rather than read through it, as O_NOFOLLOW does with ELOOP.
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a reparse point", path.display()),
        ));
    }
    Ok(file)
}

pub(super) fn is_private(file: &File) -> io::Result<bool> {
    let user = ProcessUser::current()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the handle is live for the call; the out-pointers are valid and
    // `descriptor` is freed below with LocalFree, as documented.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // SAFETY: `owner` and `dacl` point into `descriptor`, freed just after.
    let private = unsafe { owner_only(owner, dacl, &user) };
    // SAFETY: allocated by GetSecurityInfo for us to free.
    unsafe { LocalFree(descriptor) };
    private
}

/// Owned by `user`, and no allow entry names anyone but `user`, SYSTEM or
/// Administrators. A NULL DACL grants everyone everything.
unsafe fn owner_only(owner: PSID, dacl: *const ACL, user: &ProcessUser) -> io::Result<bool> {
    // SAFETY (whole fn): the caller passes an owner SID and ACL from one live
    // security descriptor; GetAce yields pointers into that ACL.
    unsafe {
        if owner.is_null() || !user.owns(owner) || dacl.is_null() {
            return Ok(false);
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        if GetAclInformation(
            dacl,
            (&raw mut info).cast::<c_void>(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        for index in 0..info.AceCount {
            let mut ace: *mut c_void = null_mut();
            if GetAce(dacl, index, &mut ace) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*ace.cast::<ACE_HEADER>();
            if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
                continue; // applies to children only, not to this object
            }
            match u32::from(header.AceType) {
                ACCESS_DENIED_ACE_TYPE => {}
                ACCESS_ALLOWED_ACE_TYPE => {
                    let sid = (&raw const (*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                        .cast_mut()
                        .cast::<c_void>();
                    let trusted = user.owns(sid)
                        || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                        || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0;
                    if !trusted {
                        return Ok(false);
                    }
                }
                // Callback, object and conditional ACEs can grant too; no
                // partial trust.
                _ => return Ok(false),
            }
        }
        Ok(true)
    }
}

pub(super) fn create_private_new(path: &Path) -> io::Result<File> {
    let security = OwnerOnly::new(false)?;
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; `security` outlives the call.
    // CREATE_NEW never opens an existing file or follows a link at `path`.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            // The DACL decides who; sharing read and delete lets tempfile
            // remove or rename it while open. Writers stay excluded.
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            security.security_attributes(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh handle owned by nothing else.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

/// Windows opens a directory as a file only with backup semantics.
pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

pub(super) fn restrict_directory(path: &Path) -> io::Result<()> {
    let security = OwnerOnly::new(true)?;
    let mut name = wide(path);
    // SAFETY: `name` is NUL-terminated and `security`'s ACL outlives the call.
    // The owner always holds WRITE_DAC, so this works on our own directory.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            security.acl(),
            null_mut(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

pub(super) fn create_dir_all(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}
