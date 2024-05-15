<?php

namespace App\Controller;

use App\Entity\User;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;

class SecurityController extends AbstractController
{

    #[Route(path: '/api/login', name: 'app_login', methods: ['POST'])]
    public function login(Request $request, EntityManagerInterface $entityManager, UserPasswordHasherInterface $passwordHasher, JWTTokenManagerInterface $JWTManager): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'];
        $password = $data['password'];

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user) {
            return $this->json(['message' => 'User not found'], Response::HTTP_UNAUTHORIZED);
        }
        if (!$user->isVerified()) {
            return $this->json(['message' => 'User not verified'], Response::HTTP_UNAUTHORIZED);
        }
        if (!$passwordHasher->isPasswordValid($user, $password)) {
            return $this->json(['message' => 'Invalid credentials'], Response::HTTP_UNAUTHORIZED);
        }


        $token = $JWTManager->create($user);

        return $this->json(['token' => $token]);
    }
    #[Route(path: '/api/token/check', name: 'app_check_token', methods: ['GET'])]
    public function checkToken(?UserInterface $user): JsonResponse
    {
        if (!$user) {
            return new JsonResponse(['success' => false, 'message' => 'No token or invalid token provided.'], JsonResponse::HTTP_FORBIDDEN);
        }

        return new JsonResponse([
            'success' => true,
            'userId' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
        ]);
    }
    #[Route(path: '/api/resource', name: 'app_get_resource', methods: ['GET'])]
    public function getResource(?UserInterface $user): JsonResponse
    {
        if (!$user) {
            return new JsonResponse(['error' => 'Access Denied'], JsonResponse::HTTP_FORBIDDEN);
        }

        $resourceData = [
            'userId' => $user->getId(),
            'data' => 'Some protected resource data here...'
        ];

        return new JsonResponse($resourceData);
    }
}
