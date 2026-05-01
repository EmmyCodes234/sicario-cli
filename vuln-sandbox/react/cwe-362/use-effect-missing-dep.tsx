// VULNERABLE: ReactUseEffectMissingDep — useEffect with empty dependency array uses stale closure variable
// Rule: ReactUseEffectMissingDep | CWE-362 (Race Condition / Concurrent Execution Using Shared Resource)
// Pattern: useEffect(() => { fetchData(userId) }, []) — userId changes are silently ignored (stale closure)

import React, { useState, useEffect } from 'react';

interface UserProfile {
  id: string;
  name: string;
  email: string;
}

interface ProfileViewerProps {
  userId: string;
}

const ProfileViewer: React.FC<ProfileViewerProps> = ({ userId }) => {
  const [profile, setProfile] = useState<UserProfile | null>(null);

  // VULNERABLE: empty dependency array [] means this effect only runs once on mount.
  // If userId changes (e.g. navigating between profiles), fetchData still uses the
  // stale initial userId — a race condition / stale closure bug.
  useEffect(() => {
    const fetchData = async () => {
      const response = await fetch(`/api/users/${userId}`);
      const data: UserProfile = await response.json();
      setProfile(data);
    };

    fetchData();
  }, []);

  if (!profile) return <p>Loading...</p>;

  return (
    <div className="profile">
      <h2>{profile.name}</h2>
      <p>{profile.email}</p>
    </div>
  );
};

export default ProfileViewer;
