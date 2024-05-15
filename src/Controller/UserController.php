<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mailer\Mailer;

class UserController extends AbstractController
{
    #[Route(path: '/api/register', name: 'app_register', methods: ['POST'])]
    public function register(Request $request, EntityManagerInterface $entityManager, UserPasswordHasherInterface $passwordHasher, ValidatorInterface $validator, UserRepository $userRepository, MailerInterface $mailer
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'];
        $password = $data['password'];


        if ($userRepository->findOneBy(['email' => $email])) {
            return new JsonResponse(['message' => 'Email already in use'], Response::HTTP_CONFLICT);
        }


        $user = new User();
        $user->setEmail($email);
        $user->setPassword($passwordHasher->hashPassword($user, $password));
        $user->setRoles(['ROLE_USER']);


        $token = bin2hex(random_bytes(32));
        $user->setVerificationToken($token);

        $entityManager->persist($user);
        $entityManager->flush();


        $verificationUrl = $this->generateUrl('app_verify_email', ['token' => $token], UrlGeneratorInterface::ABSOLUTE_URL);

        $transport = new EsmtpTransport('smtp.poczta.onet.pl', 465, true);
        $transport->setUsername('pracadyplomowa2023@onet.pl');
        $transport->setPassword('Maciek12@');

        $mailer = new Mailer($transport);

        $email = (new Email())
            ->from('pracadyplomowa2023@onet.pl')
            ->to($user->getEmail())
            ->subject('Verify your email')
            ->html("Please click on the following link to verify your email: <a href=\"$verificationUrl\">Verify Email</a>");

        $mailer->send($email);

        return new JsonResponse(['message' => 'User registered successfully, please check your email to verify it.'], Response::HTTP_CREATED);
    }

    #[Route('/verify/email/{token}', name: 'app_verify_email')]
    public function verifyUserEmail(string $token, EntityManagerInterface $entityManager): Response
    {
        $user = $entityManager->getRepository(User::class)->findOneBy(['verificationToken' => $token]);

        if (!$user) {
            throw $this->createNotFoundException('This verification token is invalid.');
        }

        $user->setIsVerified(true);
        $user->setVerificationToken(null);
        $entityManager->flush();

        return new JsonResponse(['message' => 'Email verified successfully!']);
    }

}