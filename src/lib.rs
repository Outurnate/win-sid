//! Crate for parsing [Windows security identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) without depending on any Windows-only APIs.  This crate is capable of parsing SIDs from their canonical string representation (e.g. S-1-5-21-1004336348-1177238915-682003330-512) as well as their canonical binary representation found within binary SDDLs, LDAP attributes, etc.

pub use win_sid_core::IdentifierAuthority;
pub use win_sid_core::SecurityIdentifier;
pub use win_sid_core::SecurityIdentifierError;
pub use win_sid_macros::sid;

/// Module contains all well-known static SIDs as well as functions for generating well-known SIDs that are relative to another resource.  For example, the Domain Admins group has the same relative identifier in every domain, but the sub authority is unique per domain.
pub mod well_known {
    #![allow(non_snake_case)]

    use ::win_sid_core as win_sid;
    use std::sync::LazyLock;
    use win_sid_core::SecurityIdentifier;
    use win_sid_macros::sid;

    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab

    /// No Security principal. Used when the SID is unknown.
    pub static NULL: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-0-0"));

    /// WORLD. A group that includes all users.
    pub static EVERYONE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-1-0"));

    /// A group that includes all users who have physically logged on locally.
    pub static LOCAL: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-2-0"));
    /// A group that includes users who are logged on to the physical console. This SID can be used to implement security policies that grant different rights based on whether a user has been granted physical access to the console.
    pub static CONSOLE_LOGIN: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-2-1"));

    /// A group with creator authority.
    pub static CREATOR_AUTHORITY: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-3"));
    /// A placeholder in an inheritable access control entry (ACE). When the ACE is inherited, the system replaces this SID with the SID for the object's creator.
    pub static CREATOR_OWNER: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-3-0"));
    /// A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the primary group of the object's creator.
    pub static CREATOR_GROUP: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-3-1"));
    /// A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the object's owner server.
    pub static OWNER_SERVER: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-3-2"));
    /// A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the object's group server.
    pub static GROUP_SERVER: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-3-3"));
    /// A group that represents the current owner of the object. When an ACE that carries this SID is applied to an object, the system ignores the implicit READ_CONTROL and WRITE_DAC permissions for the object owner.
    pub static OWNER_RIGHTS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-3-4"));

    /// A SID containing only the SECURITY_NT_AUTHORITY identifier authority.
    pub static NT_AUTHORITY: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5"));
    /// A group that includes all users who have logged on through a dial-up connection.
    pub static DIALUP: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-1"));
    /// A group that includes all users who have logged on through a network connection.
    pub static NETWORK: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-2"));
    /// A group that includes all users who have logged on through a batch queue facility.
    pub static BATCH: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-3"));
    /// A group that includes all users who have logged on interactively.
    pub static INTERACTIVE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-4"));
    /// A logon session. The X and Y values for these SIDs are different for each logon session and are recycled when the operating system is restarted.
    pub fn LOGON_ID(x: u32, y: u32) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[5, x, y])
    }
    /// A group that includes all security principals that have logged on as a service.
    pub static SERVICE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-6"));
    /// A group that represents an anonymous logon.
    pub static ANONYMOUS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-7"));
    /// Identifies a SECURITY_NT_AUTHORITY Proxy.
    pub static PROXY: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-8"));
    /// A group that includes all domain controllers in a forest that uses an Active Directory directory service.
    pub static ENTERPRISE_DOMAIN_CONTROLLERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-9"));
    /// A placeholder in an inheritable ACE on an account object or group object in Active Directory. When the ACE is inherited, the system replaces this SID with the SID for the security principal that holds the account.
    pub static PRINCIPAL_SELF: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-10"));
    /// A group that includes all users whose identities were authenticated when they logged on. Users authenticated as Guest or Anonymous are not members of this group.
    pub static AUTHENTICATED_USERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-11"));
    /// This SID is used to control access by untrusted code. ACL validation against tokens with RC consists of two checks, one against the token's normal list of SIDs and one against a second list (typically containing RC - the "RESTRICTED_CODE" token - and a subset of the original token SIDs). Access is granted only if a token passes both tests. Any ACL that specifies RC must also specify WD - the "EVERYONE" token. When RC is paired with WD in an ACL, a superset of "EVERYONE", including untrusted code, is described.
    pub static RESTRICTED_CODE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-12"));
    /// A group that includes all users who have logged on to a Terminal Services server.
    pub static TERMINAL_SERVER_USER: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-13"));
    /// A group that includes all users who have logged on through a terminal services logon.
    pub static REMOTE_INTERACTIVE_LOGON: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-14"));
    /// A group that includes all users from the same organization. If this SID is present, the OTHER_ORGANIZATION SID MUST NOT be present.
    pub static THIS_ORGANIZATION: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-15"));
    /// An account that is used by the default Internet Information Services (IIS) user.
    pub static IUSR: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-17"));
    /// An account that is used by the operating system.
    pub static LOCAL_SYSTEM: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-18"));
    /// A local service account.
    pub static LOCAL_SERVICE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-19"));
    /// A network service account.
    pub static NETWORK_SERVICE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-20"));
    /// Device identity is included in the Kerberos service ticket. If a forest boundary was crossed, then claims transformation occurred.
    pub static COMPOUNDED_AUTHENTICATION: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-21-0-0-0-496"));
    /// Claims were queried for in the account's domain, and if a forest boundary was crossed, then claims transformation occurred.
    pub static CLAIMS_VALID: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-21-0-0-0-497"));
    /// A universal group containing all read-only domain controllers in a forest.
    pub fn ENTERPRISE_READONLY_DOMAIN_CONTROLLERS(root_domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, root_domain_id[0], root_domain_id[1], root_domain_id[2], 498])
    }
    /// A user account for the system administrator. By default, it is the only user account that is given full control over the system.
    pub fn ADMINISTRATOR(machine_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, machine_id[0], machine_id[1], machine_id[2], 500])
    }
    /// A user account for people who do not have individual accounts. This user account does not require a password. By default, the Guest account is disabled.
    pub fn GUEST(machine_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, machine_id[0], machine_id[1], machine_id[2], 501])
    }
    /// A service account that is used by the Key Distribution Center (KDC) service.
    pub fn KRBTGT(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 502])
    }
    /// A global group whose members are authorized to administer the domain. By default, the DOMAIN_ADMINS group is a member of the Administrators group on all computers that have joined a domain, including the domain controllers. DOMAIN_ADMINS is the default owner of any object that is created by any member of the group.
    pub fn DOMAIN_ADMINS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 512])
    }
    /// A global group that includes all user accounts in a domain.
    pub fn DOMAIN_USERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 513])
    }
    /// A global group that has only one member, which is the built-in Guest account of the domain.
    pub fn DOMAIN_GUESTS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 514])
    }
    /// A global group that includes all clients and servers that have joined the domain.
    pub fn DOMAIN_COMPUTERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 515])
    }
    /// A global group that includes all domain controllers in the domain.
    pub fn DOMAIN_DOMAIN_CONTROLLERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 516])
    }
    /// A global group that includes all computers that are running an enterprise certification authority. Cert Publishers are authorized to publish certificates for User objects in Active Directory.
    pub fn CERT_PUBLISHERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 517])
    }
    /// A universal group in a native-mode domain, or a global group in a mixed-mode domain. The group is authorized to make schema changes in Active Directory.
    pub fn SCHEMA_ADMINISTRATORS(root_domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, root_domain_id[0], root_domain_id[1], root_domain_id[2], 518])
    }
    /// A universal group in a native-mode domain, or a global group in a mixed-mode domain. The group is authorized to make forestwide changes in Active Directory, such as adding child domains.
    pub fn ENTERPRISE_ADMINS(root_domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, root_domain_id[0], root_domain_id[1], root_domain_id[2], 519])
    }
    /// A global group that is authorized to create new Group Policy Objects in Active Directory.
    pub fn GROUP_POLICY_CREATOR_OWNERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 520])
    }
    /// A global group that includes all read-only domain controllers.
    pub fn READONLY_DOMAIN_CONTROLLERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 521])
    }
    /// A global group that includes all domain controllers in the domain that can be cloned.
    pub fn CLONEABLE_CONTROLLERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 522])
    }
    /// A global group that is afforded additional protections against authentication security threats.
    pub fn PROTECTED_USERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 525])
    }
    /// A security group for delegated write access on the msdsKeyCredentialLink attribute only. The group is intended for use in scenarios where trusted external authorities (for example, Active Directory Federated Services) are responsible for modifying this attribute. Only trusted administrators should be made a member of this group.
    pub fn KEY_ADMINS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 526])
    }
    /// A security group for delegated write access on the msdsKeyCredentialLink attribute only. The group is intended for use in scenarios where trusted external authorities (for example, Active Directory Federated Services) are responsible for modifying this attribute. Only trusted enterprise administrators should be made a member of this group.
    pub fn ENTERPRISE_KEY_ADMINS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 527])
    }
    /// A domain local group for Remote Access Services (RAS) servers. By default, this group has no members. Servers in this group have Read Account Restrictions and Read Logon Information access to User objects in the Active Directory domain local group.
    pub fn RAS_SERVERS(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 553])
    }
    /// Members in this group can have their passwords replicated to all read-only domain controllers in the domain.
    pub fn ALLOWED_RODC_PASSWORD_REPLICATION_GROUP(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 571])
    }
    /// Members in this group cannot have their passwords replicated to all read-only domain controllers in the domain.
    pub fn DENIED_RODC_PASSWORD_REPLICATION_GROUP(domain_id: [u32; 3]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[21, domain_id[0], domain_id[1], domain_id[2], 572])
    }
    /// A built-in group. After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Administrators group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Administrators group also is added to the Administrators group.
    pub static BUILTIN_ADMINISTRATORS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-544"));
    /// A built-in group. After the initial installation of the operating system, the only member is the Authenticated Users group. When a computer joins a domain, the Domain Users group is added to the Users group on the computer.
    pub static BUILTIN_USERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-545"));
    /// A built-in group. The Guests group allows users to log on with limited privileges to a computer's built-in Guest account.
    pub static BUILTIN_GUESTS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-546"));
    /// A built-in group. Power users can perform the following actions:
    /// - Create local users and groups.
    /// - Modify and delete accounts that they have created.
    /// - Remove users from the Power Users, Users, and Guests groups.
    /// - Install programs.
    /// - Create, manage, and delete local printers.
    /// - Create and delete file shares.
    pub static POWER_USERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-547"));
    /// A built-in group that exists only on domain controllers. Account Operators have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units of Active Directory except the Built-in container and the Domain Controllers OU. Account Operators do not have permission to modify the Administrators and Domain Administrators groups, nor do they have permission to modify the accounts for members of those groups.
    pub static ACCOUNT_OPERATORS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-548"));
    /// A built-in group that exists only on domain controllers. Server Operators can perform the following actions:
    /// - Log on to a server interactively.
    /// - Create and delete network shares.
    /// - Start and stop services.
    /// - Backup and restore files.
    /// - Format the hard disk of a computer.
    /// - Shut down the computer.
    pub static SERVER_OPERATORS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-549"));
    /// A built-in group that exists only on domain controllers. Print Operators can manage printers and document queues.
    pub static PRINTER_OPERATORS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-550"));
    /// A built-in group. Backup Operators can back up and restore all files on a computer, regardless of the permissions that protect those files.
    pub static BACKUP_OPERATORS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-551"));
    /// A built-in group that is used by the File Replication Service (FRS) on domain controllers.
    pub static REPLICATOR: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-552"));
    /// Builtin\Pre-Windows 2000 Compatible Access. A backward compatibility group that allows read access on all users and groups in the domain.
    pub static ALIAS_PREW2KCOMPACC: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-554"));
    /// An alias. Members of this group are granted the right to log on remotely.
    pub static REMOTE_DESKTOP: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-555"));
    /// An alias. Members of this group can have some administrative privileges to manage configuration of networking features.
    pub static NETWORK_CONFIGURATION_OPS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-556"));
    /// An alias. Members of this group can create incoming, one-way trusts to this forest.
    pub static INCOMING_FOREST_TRUST_BUILDERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-557"));
    /// An alias. Members of this group have remote access to monitor this computer.
    pub static PERFMON_USERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-558"));
    /// An alias. Members of this group have remote access to schedule the logging of performance counters on this computer.
    pub static PERFLOG_USERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-559"));
    /// An alias. Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects.
    pub static WINDOWS_AUTHORIZATION_ACCESS_GROUP: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-560"));
    /// An alias. A group for Terminal Server License Servers.
    pub static TERMINAL_SERVER_LICENSE_SERVERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-561"));
    /// An alias. A group for COM to provide computer-wide access controls that govern access to all call, activation, or launch requests on the computer.
    pub static DISTRIBUTED_COM_USERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-562"));
    /// A built-in group account for IIS users.
    pub static IIS_IUSRS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-568"));
    /// A built-in group account for cryptographic operators.
    pub static CRYPTOGRAPHIC_OPERATORS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-569"));
    /// A built-in local group.  Members of this group can read event logs from the local machine.
    pub static EVENT_LOG_READERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-573"));
    /// A built-in local group. Members of this group are allowed to connect to Certification Authorities in the enterprise.
    pub static CERTIFICATE_SERVICE_DCOM_ACCESS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-574"));
    /// Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
    pub static RDS_REMOTE_ACCESS_SERVERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-575"));
    /// A group that enables member servers to run virtual machines and host sessions.
    pub static RDS_ENDPOINT_SERVERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-576"));
    /// A group that allows members to access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service).
    pub static RDS_MANAGEMENT_SERVERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-577"));
    /// A group that gives members access to all administrative features of Hyper-V.
    pub static HYPER_V_ADMINS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-578"));
    /// A local group that allows members to remotely query authorization attributes and permissions for resources on the local computer.
    pub static ACCESS_CONTROL_ASSISTANCE_OPS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-579"));
    /// Members of this group can access Windows Management Instrumentation (WMI) resources over management protocols (such as WS-Management [DMTF-DSP0226]). This applies only to WMI namespaces that grant access to the user.
    pub static REMOTE_MANAGEMENT_USERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-580"));
    /// A local group that represents storage replica admins.
    pub static STORAGE_REPLICA_ADMINS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-32-582"));
    /// A SID that allows objects to have an ACL that lets any service process with a write-restricted token to write to the object.
    pub static WRITE_RESTRICTED_CODE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-33"));
    /// A SID that is used when the NTLM authentication package authenticated the client.
    pub static NTLM_AUTHENTICATION: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-64-10"));
    /// A SID that is used when the SChannel authentication package authenticated the client.
    pub static SCHANNEL_AUTHENTICATION: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-64-14"));
    /// A SID that is used when the Digest authentication package authenticated the client.
    pub static DIGEST_AUTHENTICATION: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-64-21"));
    /// A SID that indicates that the client's Kerberos service ticket's PAC contained a NTLM_SUPPLEMENTAL_CREDENTIAL structure (as specified in [MS-PAC] section 2.6.4). If the OTHER_ORGANIZATION SID is present, then this SID MUST NOT be present.
    pub static THIS_ORGANIZATION_CERTIFICATE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-65-1"));
    /// An NT Service account prefix.
    pub static NT_SERVICE: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-80"));
    /// A group that includes all service processes that are configured on the system. Membership is controlled by the operating system.
    pub static NT_SERVICE_ALL_SERVICES: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-80-0"));
    /// The SID gives the DPS service access to coordinate execution of diagnostics/troubleshooting/resolution. The Diagnostic Policy Service is a Win32 service that runs as NT AUTHORITY\LocalService in a shared process of svchost.exe.
    pub static NT_SERVICE_DPS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-80-2970612574-78537857-698502321-558674196-1451644582"));
    /// The Diagnostics Service Host (wdiservicehost) account is granted the SeSystemProfilePrivilege where it's added to the local SAM of the machine, picked up by SCE, then added to the GPTTMPL.INF. The WdiServiceHost service enables problem detection, troubleshooting, and resolution for Windows components. The SID gives the service access to run certain system diagnostic, troubleshooting, and resolution routines.
    pub static NT_SERVICE_WDISERVICEHOST: LazyLock<SecurityIdentifier> =
        LazyLock::new(|| sid!("S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"));
    /// A built-in group. The group is created when the Hyper-V role is installed. Membership in the group is maintained by the Hyper-V Management Service (VMMS). Requires the Create Symbolic Links right (SeCreateSymbolicLinkPrivilege) and the Log on as a Service right (SeServiceLogonRight).
    pub static NT_VIRTUAL_MACHINE_VIRTUAL_MACHINES: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-83-0"));
    /// The VM SID is only used for local access, while remote access uses the machine identity.
    pub fn NT_VIRTUAL_MACHINE_REMOTE_VIRTUAL_MACHINE(container_id: [u32; 4]) -> SecurityIdentifier {
        SecurityIdentifier::new(5, &[83, 1, container_id[0], container_id[1], container_id[2], container_id[3]])
    }
    /// Identifies a user-mode driver process.
    pub static USER_MODE_DRIVERS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-84-0-0-0-0-0"));
    /// A built-in group that is used by the Desktop Windows Manager (DWM). DWM is a Windows service that manages information display for Windows applications. It is a pseudo group which all virtual accounts that are window managers get.
    pub static WINDOWS_MANAGER_WINDOWS_MANAGER_GROUP: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-90-0"));
    /// A group that includes all users who are local accounts.
    pub static LOCAL_ACCOUNT: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-113"));
    /// A group that includes all users who are local accounts and members of the administrators group.
    pub static LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-114"));
    /// A group that includes all users and computers from another organization. If this SID is present, THIS_ORGANIZATION SID MUST NOT be present.
    pub static OTHER_ORGANIZATION: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-5-1000"));

    /// All applications running in an app package context.
    pub static ALL_APP_PACKAGES: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-15-2-1"));

    /// An untrusted integrity level.
    pub static ML_UNTRUSTED: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-0"));
    /// A low integrity level.
    pub static ML_LOW: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-4096"));
    /// A medium integrity level.
    pub static ML_MEDIUM: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-8192"));
    /// A medium-plus integrity level.
    pub static ML_MEDIUM_PLUS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-8448"));
    /// A high integrity level.
    pub static ML_HIGH: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-12288"));
    /// A system integrity level.
    pub static ML_SYSTEM: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-16384"));
    /// A protected-process integrity level.
    pub static ML_PROTECTED_PROCESS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-20480"));
    /// A secure process integrity level.
    pub static ML_SECURE_PROCESS: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-16-28672"));

    /// A SID that means the client's identity is asserted by an authentication authority based on proof of possession of client credentials.
    pub static AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-18-1"));
    /// A SID that means the client's identity is asserted by a service.
    pub static SERVICE_ASSERTED_IDENTITY: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-18-2"));
    /// A SID that means the client's identity is asserted by an authentication authority based on proof of current possession of client public key credentials.
    pub static FRESH_PUBLIC_KEY_IDENTITY: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-18-3"));
    /// A SID that means the client's identity is based on proof of possession of public key credentials using the key trust object.
    pub static KEY_TRUST_IDENTITY: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-18-4"));
    /// A SID that means the key trust object had the multifactor authentication (MFA) property.
    pub static KEY_PROPERTY_MFA: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-18-5"));
    /// A SID that means the key trust object had the attestation property.
    pub static KEY_PROPERTY_ATTESTATION: LazyLock<SecurityIdentifier> = LazyLock::new(|| sid!("S-1-18-6"));
}
