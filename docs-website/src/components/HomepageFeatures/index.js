import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Constrain',
    description: (
      <>
        Define what AI agents can do with signed <code>.aflock</code> policy files.
        Set spend limits, tool restrictions, file access patterns, and domain allowlists.
      </>
    ),
  },
  {
    title: 'Attest',
    description: (
      <>
        Agent actions produce cryptographically signed in-toto attestations via DSSE envelopes.
        Built on <a href="/docs/docs/ecosystem/rookery">Rookery</a>, a security-hardened attestation framework by <a href="https://testifysec.com">TestifySec</a>.
      </>
    ),
  },
  {
    title: 'Verify',
    description: (
      <>
        Verify constraint compliance with a 6-phase verification algorithm.
        Signature verification is implemented; identity, Rego, AI evaluation, and sublayout recursion are <a href="https://github.com/aflock-ai/aflock/issues/16">in active development</a>.
      </>
    ),
  },
];

function Feature({title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center padding-horiz--md" style={{paddingTop: '2rem'}}>
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
