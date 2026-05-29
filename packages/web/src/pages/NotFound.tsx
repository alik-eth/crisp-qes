import { Link } from "wouter";

export function NotFound() {
    return (
        <section className="section">
            <h1>Not found</h1>
            <p className="muted">The page you’re looking for doesn’t exist.</p>
            <p style={{ marginTop: 16 }}>
                <Link href="/petitions" className="btn btn--ghost btn--sm">
                    Back to petitions
                </Link>
            </p>
        </section>
    );
}
