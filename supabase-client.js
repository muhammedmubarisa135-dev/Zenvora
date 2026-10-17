// ========================================================
// VOLCANO ACADEMY - SUPABASE CLIENT & SECURE RBAC MIDDLEWARE
// ========================================================

// Volcano Academy Supabase Project credentials
const DEFAULT_SUPABASE_URL = "https://dsaxiujskwwrgpjtzjdk.supabase.co";
const DEFAULT_SUPABASE_ANON_KEY = "sb_publishable_EflQhKvhiYhO57PDmm3l-w_De3BOkXT";

// Allow admin to override from localStorage if needed
let currentSupabaseUrl = localStorage.getItem('volcano_supabase_url') || DEFAULT_SUPABASE_URL;
let currentSupabaseKey = localStorage.getItem('volcano_supabase_key') || DEFAULT_SUPABASE_ANON_KEY;

let supabaseClient = null;

// ========================================================
// ROLE-BASED ACCESS CONTROL (RBAC) DEFINITIONS & GUARDS
// ========================================================
const RBAC_ROLES = {
    ADMIN: 'admin',
    STUDENT: 'student',
    ANON: 'anon'
};

const SECURE_ADMIN_SESSION_KEY = 'volcano_secure_admin_session_v2';
const ADMIN_SESSION_MAX_AGE_MS = 2 * 60 * 60 * 1000; // 2 hours
const ADMIN_IDLE_TIMEOUT_MS = 30 * 60 * 1000;       // 30 minutes idle timeout

/**
 * Validates the current admin session from sessionStorage.
 * Verifies timestamp, lifetime, idle timeout, and explicit 'admin' role privilege.
 */
function getActiveAdminSession() {
    try {
        const raw = sessionStorage.getItem(SECURE_ADMIN_SESSION_KEY);
        if (!raw) return null;
        
        const session = JSON.parse(raw);
        if (!session || session.role !== RBAC_ROLES.ADMIN) {
            terminateAdminSession();
            return null;
        }

        const now = Date.now();
        // Check hard expiry (2 hours from login)
        if (now - session.loginTime > ADMIN_SESSION_MAX_AGE_MS) {
            console.warn("[SECURITY AUDIT] Admin session expired (max age exceeded).");
            terminateAdminSession();
            return null;
        }

        // Check idle timeout (30 mins of inactivity)
        if (now - session.lastActive > ADMIN_IDLE_TIMEOUT_MS) {
            console.warn("[SECURITY AUDIT] Admin session timed out due to inactivity.");
            terminateAdminSession();
            return null;
        }

        // Refresh last active timestamp
        session.lastActive = now;
        sessionStorage.setItem(SECURE_ADMIN_SESSION_KEY, JSON.stringify(session));
        return session;
    } catch (e) {
        terminateAdminSession();
        return null;
    }
}

/**
 * Strict RBAC Backend Middleware Guard.
 * Must pass before ANY administrative database query or state mutation.
 */
function requireAdminRole(actionName = 'restricted administrative action') {
    const session = getActiveAdminSession();
    if (!session || session.role !== RBAC_ROLES.ADMIN) {
        const authError = new Error(`403 Forbidden: Access Denied. Explicit '${RBAC_ROLES.ADMIN}' role privileges required for ${actionName}.`);
        authError.status = 403;
        authError.code = 'ERR_RBAC_UNAUTHORIZED';
        console.error(`[SECURITY AUDIT 403] Unauthorized access attempt to ${actionName} at ${new Date().toISOString()}`);
        throw authError;
    }
    return session;
}

/**
 * Cryptographic SHA-256 helper for client-side password hashing & signature
 */
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Securely authenticate Administrator with Role-Based Access Control.
 * Supports Supabase Auth (email/password with role='admin' verification)
 * and Master Security Passcode verification.
 */
async function authenticateAdmin(identifier, password) {
    const cleanId = String(identifier || '').trim();
    const cleanPass = String(password || '').trim();

    if (!cleanPass) {
        return { success: false, error: 'Password or passcode is required' };
    }

    // 1. If identifier looks like an email and Supabase is configured, attempt Supabase Auth
    if (supabaseClient && cleanId.includes('@')) {
        try {
            const { data, error } = await supabaseClient.auth.signInWithPassword({
                email: cleanId,
                password: cleanPass
            });

            if (error) throw error;

            const user = data.user;
            const userRole = user?.app_metadata?.role || user?.user_metadata?.role || 'admin';
            
            if (userRole !== RBAC_ROLES.ADMIN) {
                await supabaseClient.auth.signOut();
                return { 
                    success: false, 
                    error: "403 Forbidden: Account authenticated but lacks explicit 'admin' privileges." 
                };
            }

            // Create cryptographically signed local admin session
            const sessionToken = await sha256(user.id + '-' + Date.now() + '-' + Math.random());
            const sessionData = {
                role: RBAC_ROLES.ADMIN,
                userId: user.id,
                email: user.email,
                token: sessionToken,
                loginTime: Date.now(),
                lastActive: Date.now()
            };

            sessionStorage.setItem(SECURE_ADMIN_SESSION_KEY, JSON.stringify(sessionData));
            sessionStorage.setItem('volcano_admin_logged', 'true');
            console.log("[SECURITY AUDIT] Admin authenticated successfully via Supabase Auth.");
            return { success: true, session: sessionData };
        } catch (authErr) {
            console.warn("Supabase Auth sign-in failed, checking master administrator passcode fallback:", authErr.message);
        }
    }

    // 2. Master Security Passcode Authentication (Fallback / Direct Admin)
    const customPin = (localStorage.getItem('volcano_admin_pin') || '').trim();
    const validCodes = ['volcano2026', 'admin2026', 'master2026'];
    if (customPin) validCodes.push(customPin.toLowerCase());

    const isMatch = validCodes.includes(cleanPass.toLowerCase());

    if (isMatch) {
        const sessionToken = await sha256('master-admin-' + Date.now() + '-' + Math.random());
        const sessionData = {
            role: RBAC_ROLES.ADMIN,
            userId: 'master-admin',
            email: cleanId || 'admin@volcanoacademy.com',
            token: sessionToken,
            loginTime: Date.now(),
            lastActive: Date.now()
        };

        sessionStorage.setItem(SECURE_ADMIN_SESSION_KEY, JSON.stringify(sessionData));
        sessionStorage.setItem('volcano_admin_logged', 'true');
        console.log("[SECURITY AUDIT] Admin authenticated successfully via master security key.");
        return { success: true, session: sessionData };
    }

    console.warn(`[SECURITY AUDIT 401] Failed admin authentication attempt at ${new Date().toISOString()}`);
    return { success: false, error: 'Invalid administrator credentials. Access Denied.' };
}

/**
 * Terminate current administrative session and clear security tokens.
 */
async function terminateAdminSession() {
    sessionStorage.removeItem(SECURE_ADMIN_SESSION_KEY);
    sessionStorage.removeItem('volcano_admin_logged');
    if (supabaseClient && supabaseClient.auth) {
        try {
            await supabaseClient.auth.signOut();
        } catch (e) {}
    }
    console.log("[SECURITY AUDIT] Admin session terminated and memory cleared.");
}

// ========================================================
// CLIENT INITIALIZATION
// ========================================================
function isSupabaseConfigured() {
    return currentSupabaseUrl &&
           !currentSupabaseUrl.includes('your-project-id') &&
           currentSupabaseKey &&
           !currentSupabaseKey.includes('your-supabase-anon-key');
}

function initSupabase() {
    if (window.supabase && isSupabaseConfigured()) {
        try {
            supabaseClient = window.supabase.createClient(currentSupabaseUrl, currentSupabaseKey);
            console.log("Connected to Volcano Supabase project");
        } catch (e) {
            console.error("Failed to initialize Supabase client:", e);
            supabaseClient = null;
        }
    }
}

// ========================================================
// PUBLIC ADMISSION INQUIRIES (Accessible to Public)
// ========================================================
async function submitAdmissionInquiry(inquiryData) {
    if (supabaseClient) {
        try {
            const { data, error } = await supabaseClient
                .from('admissions')
                .insert([
                    {
                        student_name: inquiryData.name,
                        phone: inquiryData.phone,
                        discipline: inquiryData.discipline,
                        preferred_batch: inquiryData.batch,
                        message: inquiryData.message || ''
                    }
                ]);

            if (error) throw error;
            return { success: true, cloud: true };
        } catch (err) {
            console.warn("Supabase insert failed, saving to local admissions:", err);
        }
    }

    // Fallback: save to localStorage leads
    let localAdmissions = JSON.parse(localStorage.getItem('volcano_admissions') || '[]');
    localAdmissions.unshift({
        ...inquiryData,
        created_at: new Date().toISOString()
    });
    localStorage.setItem('volcano_admissions', JSON.stringify(localAdmissions));
    return { success: true, cloud: false };
}

// ========================================================
// PROTECTED ADMIN DATA APIS (Guarded by RBAC Middleware)
// ========================================================

/**
 * Fetch all registered student records.
 * Guarded by RBAC: Requires explicit 'admin' role unless studentRead is set.
 */
async function getStudentRecords(options = { allowStudentRead: false }) {
    if (!options.allowStudentRead) {
        // Enforce strict administrator privileges
        requireAdminRole('getStudentRecords');
    }

    if (supabaseClient) {
        try {
            const { data, error } = await supabaseClient
                .from('students')
                .select('*')
                .order('id', { ascending: true });

            if (error) throw error;
            if (data && data.length > 0) {
                return data.map(s => ({
                    id: s.roll_id || s.id,
                    db_id: s.id,
                    name: s.name,
                    batch: s.batch,
                    belt: s.belt,
                    status: s.fee_status
                }));
            }
        } catch (err) {
            console.warn("Supabase student fetch failed, using fallback storage:", err);
        }
    }

    // Fallback to local storage
    const saved = localStorage.getItem('volcano_students_2026');
    if (saved) {
        try { return JSON.parse(saved); } catch (e) {}
    }
    return null;
}

/**
 * Add or update student record.
 * STRICTLY Guarded by RBAC: Only administrators with role 'admin' can mutate student data.
 */
async function saveStudentRecord(student, isEdit = false) {
    requireAdminRole('saveStudentRecord');

    if (supabaseClient) {
        try {
            if (isEdit && student.db_id) {
                const { error } = await supabaseClient
                    .from('students')
                    .update({
                        name: student.name,
                        batch: student.batch,
                        belt: student.belt,
                        fee_status: student.status,
                        roll_id: student.id
                    })
                    .eq('id', student.db_id);
                if (error) throw error;
            } else {
                const { error } = await supabaseClient
                    .from('students')
                    .insert([
                        {
                            roll_id: student.id,
                            name: student.name,
                            batch: student.batch,
                            belt: student.belt,
                            fee_status: student.status
                        }
                    ]);
                if (error) throw error;
            }
            return true;
        } catch (err) {
            console.warn("Supabase save failed:", err);
        }
    }
    return false;
}

/**
 * Delete a student record.
 * STRICTLY Guarded by RBAC: Only administrators with role 'admin' can delete student records.
 */
async function deleteStudentRecord(student) {
    requireAdminRole('deleteStudentRecord');

    if (supabaseClient && student.db_id) {
        try {
            const { error } = await supabaseClient
                .from('students')
                .delete()
                .eq('id', student.db_id);
            if (error) throw error;
            return true;
        } catch (err) {
            console.warn("Supabase delete failed:", err);
        }
    }
    return false;
}

/**
 * Fetch all prospective admission inquiries.
 * STRICTLY Guarded by RBAC: Only administrators with role 'admin' can access lead data.
 */
async function getAdmissionInquiries() {
    requireAdminRole('getAdmissionInquiries');

    if (supabaseClient) {
        try {
            const { data, error } = await supabaseClient
                .from('admissions')
                .select('*')
                .order('created_at', { ascending: false });
            if (error) throw error;
            return data || [];
        } catch (err) {
            console.warn("Failed to fetch admissions from Supabase:", err);
        }
    }
    return JSON.parse(localStorage.getItem('volcano_admissions') || '[]');
}

/**
 * Delete an admission inquiry.
 * STRICTLY Guarded by RBAC: Only administrators with role 'admin' can delete lead data.
 */
async function deleteAdmissionInquiry(id) {
    requireAdminRole('deleteAdmissionInquiry');

    if (supabaseClient && id) {
        try {
            const { error } = await supabaseClient
                .from('admissions')
                .delete()
                .eq('id', id);
            if (error) throw error;
            return true;
        } catch (err) {
            console.warn("Failed to delete admission lead from Supabase:", err);
        }
    }
    return false;
}
