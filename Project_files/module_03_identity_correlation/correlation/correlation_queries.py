def shared_certificate_query(): return "MATCH (c:Certificate)-[:COVERS_SAN]->(s:Subdomain) WITH c, collect(s.name) AS sans WHERE size(sans)>1 RETURN c.fingerprint AS fingerprint,sans"
